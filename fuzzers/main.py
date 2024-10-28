import atexit
from collections import defaultdict
import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import pathlib
import random
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time
import typing
import uuid

import google.api_core.exceptions
import google.cloud.storage as gcs
import inotify.adapters
import prometheus_client
import toml
from typing_extensions import TypedDict
import zulip

from lib import config
from workers import utils

WORKDIR = utils.WORKDIR
REPO_URL = utils.REPO_URL
#WORKDIR = pathlib.Path('/tmp')
#REPO_URL = 'https://github.com/Ekleog/nearcore'

AUTO_REFRESH_INTERVAL = datetime.timedelta(24 * 3600)
SYNC_LOG_UPLOAD_INTERVAL = datetime.timedelta(3600)
#AUTO_REFRESH_INTERVAL = datetime.timedelta(seconds=300)
#SYNC_LOG_UPLOAD_INTERVAL = datetime.timedelta(seconds=30)


def connect_to_gcs() -> gcs.Client:
    """Setup the environment to have gsutils work, and return a connection to GCS"""
    #subprocess.run(
    #    [
    #        'gcloud', 'auth', 'activate-service-account', '--key-file',
    #        GCS_CREDENTIALS_FILE
    #    ],
    #    check=True,
    #)
    return gcs.Client.from_service_account_json(str(GCS_CREDENTIALS_FILE))
    #return gcs.Client(project = 'near-nayduck')


NUM_FUZZERS = typing.cast(int, os.cpu_count())
#NUM_FUZZERS = 1

CMD_PORT = utils.FUZZER_CMD_PORT
METRICS_PORT = 5507

REPO_DIR = WORKDIR / 'fuzzed-nearcore'
LOGS_DIR = WORKDIR / 'fuzz-logs'
CORPUS_DIR = WORKDIR / 'fuzz-corpus'

ZULIPRC = config.CONFIG_DIR / 'zuliprc'
GCS_CREDENTIALS_FILE = config.CONFIG_DIR / 'credentials.json'
GCS_BUCKET = 'fuzzer'

FUZZ_BUILD_TIME = prometheus_client.Counter('fuzz_build_seconds',
                                            'Time spent building fuzzers',
                                            ['branch', 'crate', 'runner'])
FUZZ_TIME = prometheus_client.Counter('fuzz_seconds', 'Time spent fuzzing',
                                      ['branch', 'crate', 'runner', 'flags'])
FUZZ_CRASHES = prometheus_client.Counter(
    'fuzz_crashes',
    'Number of times the fuzzer process crashed (not unique crashes)',
    ['branch', 'crate', 'runner', 'flags'])
FUZZ_ARTIFACTS_FOUND = prometheus_client.Counter(
    'fuzz_artifacts_found',
    'Number of artifacts found (should be number of unique crashes)',
    ['crate', 'runner'])
FUZZ_CORPUS_UPLOADED = prometheus_client.Counter(
    'fuzz_corpus_uploaded', 'Number of elements uploaded to GCS corpus',
    ['crate', 'runner'])
FUZZ_CORPUS_DELETED = prometheus_client.Counter(
    'fuzz_corpus_deleted', 'Number of elements deleted from GCS corpus',
    ['crate', 'runner'])

BranchType = TypedDict('BranchType', {'name': str, 'weight': int})
TargetType = TypedDict('TargetType', {
    'crate': str,
    'runner': str,
    'weight': int,
    'flags': list[str]
})
ConfigType = TypedDict('ConfigType', {
    'branch': list[BranchType],
    'target': list[TargetType]
})

# Branch name -> list of reported artifacts
REPORTED_ARTIFACTS: typing.DefaultDict[str, list[str]] = defaultdict(list)


class Repository:

    def __init__(self, repo_dir: pathlib.Path, url: str):
        """Create a Repository object

        Args:
            repo_dir: path where the repository will be forked and various worktrees checked out
            url: URL to clone from
        """

        self.repo_dir = repo_dir
        self.url = url

    def clone_if_need_be(self) -> None:
        """Clone the repository from `self.url` if it is not present yet"""

        if not self.repo_dir.exists() or not (self.repo_dir /
                                              '.git-clone').exists():
            print(f'Doing initial clone of repository {self.repo_dir}',
                  file=sys.stderr)
            utils.mkdirs(self.repo_dir)
            subprocess.check_call(['git', 'clone', self.url, '.git-clone'],
                                  cwd=self.repo_dir)

    def worktree(self, branch: str) -> pathlib.Path:
        """
        Checks out a worktree on the tip of `branch` in repo at `self.url`, and return the path to
        the worktree.

        Args:
            branch: the branch that will be checked out in the returned path
        """

        worktree_path = self.repo_dir / branch
        if not worktree_path.exists():
            print(f'Doing initial checkout of branch {branch}', file=sys.stderr)
            subprocess.check_call(
                ['git', 'worktree', 'add', worktree_path, 'HEAD'],
                cwd=self.repo_dir / '.git-clone')

        print(f'Updating to latest commit of branch {branch}', file=sys.stderr)
        subprocess.check_call(
            ['git', 'fetch', self.url, f'refs/heads/{branch}'],
            cwd=worktree_path)
        subprocess.check_call(['git', 'checkout', 'FETCH_HEAD'],
                              cwd=worktree_path)
        subprocess.check_call(
            ['rustup', 'show'],  # update rustup if need be
            cwd=worktree_path,
        )

        return worktree_path

    def latest_config(self, branch: str) -> ConfigType:
        """Parses the configuration from the tip of `branch` of repo self.url

        Args:
            branch: the branch from which to fetch the latest configuration
        """

        on_master_path = self.worktree(
            'master') / 'nightly' / f'fuzz-{branch}.toml'
        if on_master_path.exists():
            return typing.cast(ConfigType, toml.load(on_master_path))
        # else, return the config from that branch
        return typing.cast(
            ConfigType,
            toml.load(self.worktree(branch) / 'nightly' / 'fuzz.toml'))


class Corpus:

    def __init__(self, directory: pathlib.Path, bucket: gcs.Bucket):
        """Create a corpus object that'll be using directory `directory`

        Args:
            directory: the directory that will hold the corpus
            bucket: the bucket with which to sync the corpus
        """
        self.dir = directory
        self.bucket = bucket
        self.inotify_threads: list[InotifyThread] = []
        self.version = '<unknown>'

    def update(self) -> None:
        """Figure out the latest version of the corpus on GCS and download it"""
        if self.inotify_threads:
            raise RuntimeError(
                'Attempted updating a corpus that has live notifiers')
        self.version = self.bucket.blob(
            'current-corpus').download_as_text().strip()

    def synchronize(self, crate: str, runner: str,
                    log_file: typing.IO[str]) -> None:
        """Download the corpus for `crate/runner` from GCS, then start a background thread
        uploading any new local changes

        Args:
            crate: the crate for which to fetch the corpus
            runner: the runner for which to fetch the corpus
            log_file: file to which to send logs detailing the syncing process
        """
        if self._sync_running_for(crate, runner):
            raise RuntimeError(
                f'Attempted to synchronize {crate}/{runner} that\'s already being synchronized'
            )
        base = pathlib.Path(crate) / runner
        self._reset_to_gcs(base / 'corpus', log_file, False)
        self._reset_to_gcs(base / 'artifacts', log_file, True)
        self._auto_upload(base / 'corpus', crate, runner, log_file, False)
        self._auto_upload(base / 'artifacts', crate, runner, log_file, True)

    def stop_synchronizing(self) -> None:
        """Stop the background thread synchronizing any new local changes"""
        for thread in self.inotify_threads:
            thread.exit_event.set()
        for thread in self.inotify_threads:
            thread.join()
        self.inotify_threads = []

    def corpus_for(self, target: TargetType) -> pathlib.Path:
        """Return the path to the corpus for target `target`

        Args:
            target: the target for which to return the corpus path
        """
        directory = self.dir / target['crate'] / target['runner'] / 'corpus'
        utils.mkdirs(directory)
        return directory

    def artifacts_for(self, target: TargetType) -> pathlib.Path:
        """Return the path to the artifacts for target `target`

        Args:
            target: the target for which to return the artifacts path
        """
        directory = self.dir / target['crate'] / target['runner'] / 'artifacts'
        utils.mkdirs(directory)
        return directory

    def _reset_to_gcs(self, path: pathlib.Path,
                      log_file: typing.IO[str],
                      is_artifacts: bool) -> None:
        """Reset `path` to its GCS contents, logging to `log_file`

        Args:
            path: path to reset to its GCS contents
            log_file: file to which to write the logs related to the synchronization process
        """
        print(f'Resetting path {self.dir}/{path} to GCS {self.version}/{path}/',
              file=sys.stderr)
        log_file.write(
            f'Resetting path {self.dir}/{path} to GCS {self.version}/{path}/\n')
        log_file.flush()
        utils.mkdirs(self.dir / path)
        cmd = ['gsutil', '-m', 'rsync']
        if not is_artifacts:
            cmd.append('-d')
        cmd += [f'gs://{self.bucket.name}/{self.version}/{path}/', self.dir / path]
        subprocess.check_call(
            cmd,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

    def _auto_upload(self, path: pathlib.Path, crate: str, runner: str,
                     log_file: typing.IO[str], is_artifacts: bool) -> None:
        """Setup a background thread automatically syncing the new local changes to GCS

        Args:
            path: the path to sync with GCS (relative to the corpus directory)
            crate: the crate that will be related to this path
            runner: the runner that will be related to this path
            log_file: the file where to send logs
            is_artifacts: True iff the path being synced is an artifacts path, meaning eg. syncing
                          deletions would be a bug
        """
        print(
            f'Setting up inotify watch to auto-upload changes to '
            f'{self.dir / path} to GCS {self.bucket.name}/{path}/',
            file=sys.stderr)
        log_file.write(f'Setting up inotify watch to auto-upload changes to '
                       f'{self.dir / path} to GCS {self.bucket.name}/{path}/\n')
        log_file.flush()
        thread = InotifyThread(crate=crate,
                               runner=runner,
                               directory=self.dir,
                               bucket=self.bucket,
                               version=self.version,
                               path=path,
                               log_file=log_file,
                               is_artifacts=is_artifacts)
        thread.start()
        self.inotify_threads.append(thread)

    def _sync_running_for(self, crate: str, runner: str) -> bool:
        """Whether a background thread is currently syncing the corpus for `crate/runner`

        Args:
            crate: the crate for which to check
            runner: the runner for which to check
        """
        return any(t.crate == crate and t.runner == runner
                   for t in self.inotify_threads)


class InotifyThread(threading.Thread):
    # pylint: disable=too-many-instance-attributes

    def __init__(
        self,
        *,
        crate: str,
        runner: str,
        directory: pathlib.Path,
        bucket: gcs.Bucket,
        version: str,
        path: pathlib.Path,
        log_file: typing.IO[str],
        is_artifacts: bool,
    ) -> None:
        """Prepare an inotify thread for execution.

        The thread can be started with `run()` method.

        Args:
            crate: The crate path from repository root where fuzzer is
                defined.
            runner: The runner name for the fuzzer.
            directory: The root of the corpus directory in use.
            bucket: The GCS bucket to which to submit local data changes.
            version: The corpus version in the GCS bucket (first path
                item, used to handle corpus minimization).
            path: The path to watch, starting from the corpus root.
            log_file: A file-like object to log the performed syncing
                operations to.
            is_artifacts: `True` iff the watched path is an artifacts
                directory (as opposed to corpus directory).  This
                impacts some of the metrics and disables the remote
                deletion logic.
        """

        super().__init__(daemon=True)
        self.crate = crate
        self.runner = runner
        self.dir = directory
        self.bucket = bucket
        self.version = version
        self.path = path
        self.log_file = log_file
        self.is_artifacts = is_artifacts

        self.exit_event = threading.Event()
        self.corpus_uploaded_metric = FUZZ_CORPUS_UPLOADED.labels(crate, runner)
        self.corpus_deleted_metric = FUZZ_CORPUS_DELETED.labels(crate, runner)
        self.artifacts_found_metric = FUZZ_ARTIFACTS_FOUND.labels(crate, runner)

    def run(self) -> None:
        """Starts the thread"""
        utils.mkdirs(self.dir / self.path)
        i = inotify.adapters.Inotify()
        i.add_watch((self.dir / self.path).as_posix())
        while not self.exit_event.is_set():
            # check for exit_event at most every second
            for event in i.event_gen(yield_nones=False, timeout_s=1):
                if self.exit_event.is_set():
                    break
                (_, event_types, _, filename) = event
                local_filename = self.dir / self.path / filename
                remote_filename = f'{self.version}/{self.path}/{filename}'

                if 'IN_CLOSE_WRITE' in event_types:
                    self.log_file.write(
                        f'Uploading new corpus item {local_filename} to GCS {remote_filename}\n'
                    )
                    self.log_file.flush()
                    try:
                        # TODO: batch uploads
                        self.bucket.blob(remote_filename).upload_from_filename(
                            local_filename)
                        if self.is_artifacts:
                            self.artifacts_found_metric.inc()
                        else:
                            self.corpus_uploaded_metric.inc()
                    except FileNotFoundError:
                        pass  # Ignore, as it'd mean the file has been deleted already

                if 'IN_DELETE' in event_types and not self.is_artifacts:
                    self.log_file.write(
                        f'Removing now-removed corpus item {local_filename} '
                        f'as GCS {remote_filename}\n')
                    self.log_file.flush()
                    try:
                        # TODO: batch
                        self.bucket.blob(remote_filename).delete()
                        self.corpus_deleted_metric.inc()
                    except google.api_core.exceptions.NotFound:
                        pass  # Ignore, as it'd mean the file isn't there already


class FuzzProcess:
    # pylint: disable=too-many-instance-attributes

    def __init__(
        self,
        *,
        corpus_vers: str,
        branch: BranchType,
        target: TargetType,
        repo_dir: pathlib.Path,
        log_relpath: pathlib.Path,
        log_fullpath: pathlib.Path,
    ):
        """
        Create a FuzzProcess object. It can be built with `.build()` and then started with
        `.start()`.

        Args:
            corpus_vers: is the version of the corpus (first path item), used only for logging
            branch: the branch from which to run this process
            target: the target to run in this branch
            repo_dir: the path to the nearcore checkout root
            log_relpath: the relative path from the log folder to the log file
            log_fullpath: the absolute path to the log file
        """

        self.corpus_vers = corpus_vers
        self.branch = branch
        self.target = target
        self.repo_dir = repo_dir
        self.log_relpath = log_relpath
        self.log_fullpath = log_fullpath
        self.log_file = open(log_fullpath, 'a', encoding='utf-8')  # pylint: disable=consider-using-with

        self.last_time = 0.
        self.time_paused: typing.Optional[float] = None
        self.proc: typing.Any = None  # There's some weirdness around brackets and Popen

        self.fuzz_build_time_metric = FUZZ_BUILD_TIME.labels(
            branch['name'], target['crate'], target['runner'])
        self.fuzz_time_metric = FUZZ_TIME.labels(branch['name'],
                                                 target['crate'],
                                                 target['runner'],
                                                 target['flags'])
        self.fuzz_crashes_metric = FUZZ_CRASHES.labels(branch['name'],
                                                       target['crate'],
                                                       target['runner'],
                                                       target['flags'])

    def build(self) -> None:
        """
        Build the fuzzer runner.

        This is a synchronous operation for convenience reasons, as cargo itself uses all the
        available cores most of the time it shouldn't be a big deal. The only drawback is that
        requests to pause/exit the fuzzer would block until the current build is completed.
        """
        print(
            f'Building fuzzer for branch {self.branch} and target '
            f'{self.target}, log is at {self.log_relpath}',
            file=sys.stderr)

        # Log metadata information
        current_commit = subprocess.check_output(('git', 'rev-parse', 'HEAD'),
                                                 cwd=self.repo_dir,
                                                 encoding='utf-8').strip()
        self.log_file.write(f'''\
Corpus version: {self.corpus_vers}
On commit {current_commit} (tip of branch {self.branch["name"]})
Target is {self.target}
Current time: {datetime.datetime.utcnow()}
On host: {socket.gethostname()}
''')
        self.log_file.flush()

        # Build the fuzzer runner
        # TODO: actually build and have build time metrics for the fuzzer runner, but this must not
        # block the pause/resume behavior
        #build_start = time.monotonic()
        #subprocess.check_call(
        #    ['cargo', 'fuzz', 'build', self.target['runner']],
        #    cwd=self.repo_dir / self.target['crate'],
        #    stdout=self.log_file,
        #    stderr=subprocess.STDOUT,
        #)
        #self.fuzz_build_time_metric.inc(time.monotonic() - build_start)

    def start(self, corpus: Corpus) -> None:
        """Start the fuzzer runner on corpus `corpus`

        Args:
            corpus: the corpus directory to use for this process
        """
        print(
            f'Starting fuzzer for branch {self.branch} and '
            f'target {self.target}, log is at {self.log_relpath}',
            file=sys.stderr)

        # Prepare the fuzz time metric
        self.last_time = time.monotonic()

        # Spin up the fuzzer process itself
        # libfuzzer will kill the process if it takes more than -timeout number of seconds.
        # nayduck can sigstop the fuzzing process for ~2 hours at most, so 8000s should be ok.
        flags = ['-timeout=8000'] + self.target['flags']
        if self.target.get('type') == 'bolero':
            self.proc = subprocess.Popen(
                [
                    'cargo',
                    'bolero',
                    'test',
                    '--fake-nightly-toolchain',
                    f'--corpus-dir={corpus.corpus_for(self.target)}',
                    f'--crashes-dir={corpus.artifacts_for(self.target)}',
                    '-p',
                    self.target['crate'],
                    self.target['runner'],
                ] + [f'--engine-args="{flag}"' for flag in flags],
                cwd = self.repo_dir,
                start_new_session = True,
                stdout = self.log_file,
                stderr = subprocess.STDOUT,
            )
        else:
            self.proc = subprocess.Popen(  # pylint: disable=consider-using-with
                [
                    'cargo',
                    'fuzz',
                    'run',
                    self.target['runner'],
                    '--',
                    str(corpus.corpus_for(self.target)),
                    str(corpus.artifacts_for(self.target)),
                    f'-artifact_prefix={corpus.artifacts_for(self.target)}/',
                ] + flags,
                cwd=self.repo_dir / self.target['crate'],
                start_new_session=True,
                stdout=self.log_file,
                stderr=subprocess.STDOUT,
            )

    def check_if_crashed(self) -> bool:
        """Checks if the current process has crashed. Returns True if it stopped.

        This function must be called regularly while the fuzzer is running in order to make sure
        the fuzzing time metrics are properly updated.

        It should not be called while the fuzzer has been paused using SIGSTOP and not yet resumed
        using SIGCONT.
        """
        if self.proc.poll() is None:
            new_time = time.monotonic()
            self.fuzz_time_metric.inc(new_time - self.last_time)
            self.last_time = new_time
            return False
        # else: Fuzz crash found
        print(
            f'Fuzzer running {self.target} has stopped, log is at {self.log_fullpath}',
            file=sys.stderr)
        self.fuzz_crashes_metric.inc()
        return True

    def report_crash(self, corpus: Corpus, bucket: gcs.Bucket) -> None:
        """Report a crash from this process.

        Args:
            corpus: the corpus from which this fuzz process was running
            bucket: the bucket with wich the corpus is being synchronized
        """
        # pylint: disable=too-many-locals

        with open(self.log_fullpath, encoding='utf-8') as log_file_r:
            log_lines = list(log_file_r)
        branch = self.branch['name']
        logs_url = f'https://storage.cloud.google.com/fuzzer/logs/{self.log_relpath}'

        # Identify the artifact path
        artifact_pattern = f'Test unit written to {corpus.artifacts_for(self.target)}/'
        artifact = '<failed detecting relevant artifact in log file>'
        for line in reversed(log_lines):
            if artifact_pattern in line:
                artifact = line.split(artifact_pattern)[1].strip()
                break

        # Check the artifact was not reported yet for this branch
        if artifact in REPORTED_ARTIFACTS[branch]:
            return
        already_reported_for = [
            other_branch for (other_branch,
                              reported_artifacts) in REPORTED_ARTIFACTS.items()
            if artifact in reported_artifacts
        ]
        REPORTED_ARTIFACTS[branch].append(artifact)

        if already_reported_for:
            already_reported_msg = f'(already reported for branches {already_reported_for})'
        else:
            already_reported_msg = ''

        # Send the information in two mesages, a short one guaranteed to succeed, then a long one
        # with the log lines that could go over the message size limit
        client = zulip.Client(config_file=str(ZULIPRC))
        gcs_artifact = shlex.quote(
            f'gs://{bucket.name}/{self.corpus_vers}/{self.target["crate"]}/'
            f'{self.target["runner"]}/artifacts/{artifact}')
        quoted_crate = shlex.quote(self.target['crate'])
        quoted_runner = shlex.quote(self.target['runner'])
        quoted_artifact = shlex.quote(
            f'artifacts/{self.target["runner"]}/{artifact}')
        client.send_message({
            'type':
                'stream',
            'to':
                'pagoda/fuzzer/private',
            'topic':
                f'{branch}: artifact {artifact}',
            'content':
                f'''\
# Fuzzer found new crash for branch *{branch}* {already_reported_msg}

Full logs are available at {logs_url}.

To reproduce, first go to the fuzzer directory:
```
cd {quoted_crate}
```

You can download the artifact by using the following command:
```
gsutil cp {gcs_artifact} {quoted_artifact}
```

Then, you can reproduce by running the following command:
```
RUSTC_BOOTSTRAP=1 cargo fuzz run {quoted_runner} {quoted_artifact}
```

Or minimize by running the following command:
```
RUSTC_BOOTSTRAP=1 cargo fuzz tmin {quoted_runner} {quoted_artifact}
```

Please edit the topic name to add more meaningful information once investigated. \
Keeping the artifact hash in it can help if the same artifact gets detected as \
crashing another branch.
'''
        })
        prepend_log_lines = '\n'.join(log_lines[:5]) + '\n[...]\n'
        focus_log_lines = ''
        for line in reversed(log_lines[5:]):
            if line.startswith('```'):
                # Censor the end of a spoiler block, not great but this is for human consumption
                # anyway
                line = ' ' + line
            if len(prepend_log_lines) + len(focus_log_lines) + len(line) > 9000:
                # Zulip limit is 10k, let's keep some safety buffer here
                break
            focus_log_lines = line + focus_log_lines
        focus_log_lines = prepend_log_lines + focus_log_lines
        client.send_message({
            'type':
                'stream',
            'to':
                'pagoda/fuzzer/private',
            'topic':
                f'{branch}: artifact {artifact}',
            'content':
                f'```spoiler First and last few log lines\n{focus_log_lines}\n```',
        })

    def signal(self, sig: int) -> None:
        """
        Signal the fuzzer process (with all its process group as a fuzzer can spawn sub-fuzzers)

        Args:
            sig: the signal to send to the fuzzer process
        """

        print(f'Sending signal {sig} to fuzzer {self.proc.pid}',
              file=sys.stderr)
        os.killpg(os.getpgid(self.proc.pid), sig)
        if sig == signal.SIGSTOP and self.time_paused is None:
            self.time_paused = time.monotonic()
        if sig == signal.SIGCONT and self.time_paused is not None:
            self.last_time += time.monotonic() - self.time_paused
            self.time_paused = None


# Actually this should also require a ['weight']: int bound but it seems like a mess to encode
T = typing.TypeVar('T')


def random_weighted(array: list[T], name: str) -> T:
    """Pick one random items from `array`, logging that as `name`

    Args:
        array: the list to pick from
        name: the name to log that choice as
    """
    print(f'Picking one random {name} among {array}', file=sys.stderr)
    untyped_array = typing.cast(typing.Any, array)
    res = random.choices(array, [x['weight'] for x in untyped_array])[0]
    print(f' -> picked {res}', file=sys.stderr)
    return res


def pause_exit_spot(pause_evt: threading.Event, resume_evt: threading.Event,
                    exit_evt: threading.Event) -> bool:
    """
    Poll the events, returning True if `exit_evt` was set and pausing as requested by `pause_evt`
    and `resume_evt`

    Args:
        pause_evt: the pausing event to poll
        resume_evt: the resuming event to poll
        exit_evt: the exiting event to poll
    """

    if pause_evt.is_set():
        while not resume_evt.wait(timeout=1):
            if exit_evt.is_set():
                return True
    return exit_evt.is_set()


def kill_fuzzers(bucket: gcs.Bucket,
                 fuzzers: typing.Iterable[FuzzProcess]) -> None:
    """Kill all the fuzzers from `fuzzers`, uploading their logs to `bucket`

    Args:
        bucket: the bucket  to submit the logs to
        fuzzers: the list of fuzzers to kill
    """
    for fuzzer in fuzzers:
        try:
            fuzzer.signal(signal.SIGTERM)
        except ProcessLookupError:
            print(f'Failed looking up process {fuzzer.proc.pid}',
                  file=sys.stderr)
    time.sleep(5)
    for fuzzer in fuzzers:
        try:
            fuzzer.signal(signal.SIGKILL)
        except ProcessLookupError:
            pass
    for fuzzer in fuzzers:
        bucket.blob(f'logs/{fuzzer.log_relpath}').upload_from_filename(
            str(LOGS_DIR / fuzzer.log_relpath))


def configure_one_fuzzer(repo: Repository, corpus: Corpus,
                         sync_log_files: list[pathlib.Path],
                         fuzzers: list[FuzzProcess]) -> FuzzProcess:
    """Configure one fuzzer process, without building or starting it

    Args:
        repo: the Repository handling the checkout
        corpus: the Corpus synchronizing the current fuzzing corpus and artifacts
        sync_log_files: a list of log file paths with details about the syncing process. One entry
                        will be added to it with this one fuzzer's sync logs
        fuzzers: the list of fuzzers, the newly-configured fuzzer will be added to it
    """
    # pylint: disable=too-many-locals

    # Read the configuration from the repository
    master_cfg = repo.latest_config('master')
    branch = random_weighted(master_cfg['branch'], 'branch')
    branch_name = branch['name']

    branch_cfg = repo.latest_config(branch_name)
    target = random_weighted(branch_cfg['target'], 'target')
    crate = target['crate']
    runner = target['runner']

    # Update cargo-fuzz if need be
    subprocess.check_call(['cargo', 'install', 'cargo-fuzz'],
                          cwd=repo.worktree(branch_name))

    # Synchronize the relevant corpus
    corpus.stop_synchronizing()
    corpus.update()
    date = datetime.datetime.utcnow().strftime('%Y-%m-%d')
    log_path = pathlib.Path('sync') / date / crate / runner / str(uuid.uuid4())
    utils.mkdirs((LOGS_DIR / log_path).parent)
    corpus_sync_log_file = open(LOGS_DIR / log_path, 'a', encoding='utf-8')  # pylint: disable=consider-using-with
    corpus.synchronize(crate, runner, corpus_sync_log_file)
    sync_log_files.append(log_path)

    # Initialize the fuzzer
    worktree = repo.worktree(branch_name)
    log_path = pathlib.Path('fuzz') / date / crate / runner / str(uuid.uuid4())
    log_file = LOGS_DIR / log_path
    utils.mkdirs(log_file.parent)
    fuzzer = FuzzProcess(corpus_vers=corpus.version,
                         branch=branch,
                         target=target,
                         repo_dir=worktree,
                         log_relpath=log_path,
                         log_fullpath=log_file)
    fuzzers.append(fuzzer)

    return fuzzer


def run_fuzzers(gcs_client: gcs.Client, pause_evt: threading.Event,
                resume_evt: threading.Event, exit_evt: threading.Event) -> None:
    """
    Run all the fuzzers until `exit_evt` gets triggered, pausing and resuming
    them based on `pause_evt` and `resume_evt`.

    Args:
        gcs_client: the client to use for syncing with the bucket
        pause_evt: the pausing event to check
        resume_evt: the resuming event to check
        exit_evt: the exiting event to check
    """
    # pylint: disable=too-many-locals,too-many-branches,too-many-return-statements

    bucket = gcs_client.bucket(GCS_BUCKET)

    repo = Repository(REPO_DIR, REPO_URL)
    repo.clone_if_need_be()

    corpus = Corpus(CORPUS_DIR, bucket)

    while True:
        if pause_exit_spot(pause_evt, resume_evt, exit_evt):
            return

        sync_log_files: typing.List[pathlib.Path] = []
        fuzzers: typing.List[FuzzProcess] = []

        # Initialize the fuzzers
        atexit.register(kill_fuzzers, bucket, fuzzers)
        for _i in range(NUM_FUZZERS):
            fuzzer = configure_one_fuzzer(repo, corpus, sync_log_files, fuzzers)
            if pause_exit_spot(pause_evt, resume_evt, exit_evt):
                return
            fuzzer.build()
            if pause_exit_spot(pause_evt, resume_evt, exit_evt):
                return
            fuzzer.start(corpus)
            if pause_exit_spot(pause_evt, resume_evt, exit_evt):
                return

        # Wait until something happens
        started = time.monotonic()
        last_sync_file_upload = started
        next_restart = started + AUTO_REFRESH_INTERVAL.total_seconds()
        while time.monotonic() < next_restart:
            # Avoid busy-looping by sleeping 1s between each loop run
            # time.sleep(1) # This actually happens in the exit_evt.is_set() just below

            # Exit event happened?
            if exit_evt.wait(timeout=1):
                kill_fuzzers(bucket, fuzzers)
                atexit.unregister(kill_fuzzers)
                return

            # Pause event happened?
            if pause_evt.is_set():
                for fuzzer in fuzzers:
                    fuzzer.signal(signal.SIGSTOP)
                while not resume_evt.wait(timeout=1):
                    if exit_evt.is_set():
                        kill_fuzzers(bucket, fuzzers)
                        atexit.unregister(kill_fuzzers)
                        return
                for fuzzer in fuzzers:
                    fuzzer.signal(signal.SIGCONT)

            # Fuzz crash found?
            done_fuzzers = [
                fuzzer for fuzzer in fuzzers if fuzzer.check_if_crashed()
            ]
            for fuzzer in done_fuzzers:
                bucket.blob(f'logs/{fuzzer.log_relpath}').upload_from_filename(
                    str(fuzzer.log_fullpath))
                fuzzer.report_crash(corpus, bucket)
                fuzzers.remove(fuzzer)

                # Start a new fuzzer
                fuzzer = configure_one_fuzzer(repo, corpus, sync_log_files,
                                              fuzzers)
                if pause_exit_spot(pause_evt, resume_evt, exit_evt):
                    return
                fuzzer.build()
                if pause_exit_spot(pause_evt, resume_evt, exit_evt):
                    return
                fuzzer.start(corpus)
                if pause_exit_spot(pause_evt, resume_evt, exit_evt):
                    return

            # Regularly upload the sync log files
            upload_interval_secs = SYNC_LOG_UPLOAD_INTERVAL.total_seconds()
            next_sync = last_sync_file_upload + upload_interval_secs
            if time.monotonic() > next_sync:
                last_sync_file_upload = time.monotonic()
                for line in sync_log_files:
                    bucket.blob(f'logs/{line}').upload_from_filename(
                        str(LOGS_DIR / line))

    # TODO: Minimize the corpus
    # TODO: Rsync the corpus from gcs more frequently, not just once per fuzzer restart
    # TODO: Add corpus size gauge metric
    # TODO: Add coverage metrics (will need to parse logs?)
    # TODO: Add metrics about overhead (time to update corpus, to build fuzzer, etc.)


def listen_for_commands(pause_event: threading.Event,
                        resume_event: threading.Event) -> None:
    """
    Spawn an HTTP server to remote control the fuzzers

    `/pause` and `/resume` respectively sigstop and sigcont the fuzzers

    Args:
        pause_event: the pausing event to trigger upon receiving a request on /pause
        resume_event: the resuming event to trigger upon receiving a request on /resume
    """

    class HTTPHandler(BaseHTTPRequestHandler):

        def do_GET(self) -> None:  # pylint: disable=invalid-name
            if self.path == '/pause':
                resume_event.clear()
                pause_event.set()
                self.send_response(200)
            elif self.path == '/resume':
                pause_event.clear()
                resume_event.set()
                self.send_response(200)
            else:
                self.send_response(404)
            self.end_headers()

    with HTTPServer(('127.0.0.1', CMD_PORT), HTTPHandler) as httpd:
        print(f'Serving command server on port {CMD_PORT}', file=sys.stderr)
        httpd.serve_forever()


def main() -> None:
    """Main function"""
    thread_exception: typing.Optional[threading.ExceptHookArgs] = None
    exception_happened_in_thread = threading.Event()

    # Make sure to cleanup upon ctrl-c or upon any exception in a thread
    def new_excepthook(args: threading.ExceptHookArgs) -> None:
        nonlocal thread_exception
        thread_exception = args
        exception_happened_in_thread.set()

    threading.excepthook = new_excepthook

    try:
        gcs_client = connect_to_gcs()

        # Start the metrics server
        prometheus_client.start_http_server(METRICS_PORT)

        # And listen for the commands that might come up
        pause_event = threading.Event()
        resume_event = threading.Event()
        threading.Thread(daemon=True,
                         target=listen_for_commands,
                         args=(pause_event, resume_event)).start()

        # Run until an exception forces us to stop
        print('Startup complete, will start running forever now',
              file=sys.stderr)
        run_fuzzers(gcs_client, pause_event, resume_event,
                    exception_happened_in_thread)

        # Finally, proxy the exception so it gets detected and acted upon by a human
        if thread_exception:
            raise typing.cast(BaseException, thread_exception.exc_value)
    except KeyboardInterrupt:
        print('Got ^C, stopping', file=sys.stderr)


if __name__ == '__main__':
    utils.setup_environ()
    os.environ['RUSTC_BOOTSTRAP'] = '1'  # Nightly is needed by cargo-fuzz
    zulip.Client(config_file=str(ZULIPRC))  # Validate the zuliprc is setup well
    main()
