import mysql.connector
import random
import string
import time

import datetime
import os
import sys

sys.path.append(os.path.abspath('../main_db'))
import common_db


def _prettify_size(size: int) -> str:
    """Returns file size in human-readable format, e.g. 10k i/o 10000."""
    if size < 1000:
        return str(size)
    for suffix in 'kMGTPEZ':
        if size < 10000:
            return '%.1f%s' % (size / 1000, suffix)
        size //= 1000
        if size < 1000:
            return str(size) + suffix
    return str(size) + 'Y'


class UIDB (common_db.DB):
    def cancel_the_run(self, run_id, status="CANCELED"):
        sql = "UPDATE tests SET finished = now(), status = %s WHERE run_id= %s and status='PENDING'"
        self._execute_sql(sql, (status, run_id))

    def get_auth_code(self, login):
        sql = "SELECT id, code FROM users WHERE name=%s"
        result = self._execute_sql(sql, (login,))
        user = result.fetchone()
        if user:
            code = user['code']
        else:
            code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
            self._insert('users', name=login, code=code)
        return code
 
    def get_github_login(self, token):
        sql = "SELECT name FROM users WHERE code=%s"
        result = self._execute_sql(sql, (token,))
        login = result.fetchone()
        if login:
            return login['name']  
        return None

    def get_all_runs(self):
        sql = "SELECT * FROM runs ORDER BY id desc LIMIT 100"
        res = self._execute_sql(sql, ())
        all = res.fetchall()
        all_runs = []
        for run in all:
            sql = "SELECT build_id, status, is_release, features FROM builds WHERE run_id=%s"
            res = self._execute_sql(sql, (run['id'],))
            builds = res.fetchall()
            # For older runs, to be able to get older data.
            if not builds:
                builds = [{'build_id': 0, 'status': 'TEST SPECIFIC', 'is_release': False, 'features': ''}] 
            for build in builds:
                sql = '''select count(IF(status='PENDING',1,NULL)) AS pending,  count(IF(status='RUNNING',1,NULL)) AS running,  
                                 count(IF(status='PASSED',1,NULL)) AS passed,  count(IF(status='IGNORED',1,NULL)) AS ignored,  
                                 count(IF(status LIKE '%FAILED%',1,NULL)) AS failed,  count(IF(status='BUILD FAILED',1,NULL)) AS build_failed,  
                                 count(IF(status='CANCELED',1,NULL)) AS canceled,  count(IF(status='TIMEOUT',1,NULL)) AS timeout 
                                 from tests where {} = %s'''
                if build['build_id'] == 0:
                    res = self._execute_sql(sql.format('run_id'), (run['id'],))
                else:
                    res = self._execute_sql(sql.format('build_id'), (build['build_id'],))
                tests = res.fetchone()
                build['tests'] = tests
            run['builds'] = builds
            all_runs.append(run)
        return all_runs

    def get_test_history_by_id(self, test_id):
        sql = "SELECT t.name, r.branch FROM tests as t, runs as r WHERE t.test_id=%s and r.id = t.run_id"
        result = self._execute_sql(sql, (test_id,))
        res = result.fetchone()
        return self.get_test_history(res["name"], res["branch"], interested_in_logs=True)
        
    def get_test_history(self, test_name, branch, interested_in_logs=False):
        sql = "SELECT t.test_id, r.requester, r.title, t.status, t.started, t.finished, r.branch, r.sha FROM tests as t, runs as r WHERE name=%s and t.run_id = r.id and r.branch=%s ORDER BY t.test_id desc LIMIT 30"
        result = self._execute_sql(sql, (test_name, branch))
        tests = result.fetchall()
        for test in tests:
            if test["finished"] is not None and test["started"] is not None:
                test["run_time"] = str(test["finished"] - test["started"])
            if interested_in_logs:
                sql = '''SELECT type, size, storage, stack_trace, patterns
                           FROM logs
                          WHERE test_id = %s
                          ORDER BY type'''
                res = self._execute_sql(sql, (test["test_id"],))
                logs = test['logs'] = res.fetchall()
                for log in logs:
                    log['full_size'] = _prettify_size(log.pop('size'))
        return tests
            
    def get_one_run(self, run_id):
        run_data = self.get_data_about_run(run_id)
        branch = run_data["branch"] 
        
        sql = "SELECT build_id, is_release, features FROM builds WHERE run_id=%s"
        res = self._execute_sql(sql, (run_id,))
        builds = res.fetchall()
        if not builds:
            builds = [{'build_id': 0, 'status': 'TEST SPECIFIC', 'is_release': False, 'features': ''}] 
        builds_dict = {}
        for build in builds:
            builds_dict[build['build_id']] = build

        sql = "SELECT * FROM tests WHERE run_id=%s ORDER BY FIELD(status, 'FAILED', 'TIMEOUT', 'IGNORED' , 'PASSED', 'CANCELED', 'RUNNING', 'PENDING'), started"
        res = self._execute_sql(sql, (run_id,))
        a_run = res.fetchall()
        for test in a_run:
            if test['build_id'] is None:
                 test['build_id'] = 0
            test['build'] = builds_dict[test['build_id']]
            test.update(self.get_data_about_test(test, branch, blob=False))
        return a_run

    def get_data_about_test(self, test, branch, blob=False):
        columns = 'type, size, storage, stack_trace, patterns'
        if blob:
            columns += ', log'
        sql = f'SELECT {columns} FROM logs WHERE test_id = %s ORDER BY type'
        test["logs"] = {}
        for log in self._execute_sql(sql, (test['test_id'],)).fetchall():
            log['full_size'] = _prettify_size(log.pop('size'))
            if blob:
                log['log'] = log['log'].decode('utf-8', 'replace')
            test['logs'][log['type']] = log
        test['cmd'] = test["name"]
        if '--features' in test["name"]:
            test["name"] =  test["name"][ : test["name"].find('--features')]
        spl = test["name"].split(' ')
        test_l = []
        for s in spl:
            if not s.startswith("--"):
                test_l.append(s)
        test["name"] = ' '.join(test_l)
        if test["finished"] is not None and test["started"] is not None:
            test["test_time"] = str(test["finished"] - test["started"])
        history = self.get_test_history(test["cmd"], branch)
        test["history"] = self.history_stats(history)
        return test

    def get_data_about_run(self, run_id):
        sql = "SELECT * from runs WHERE id = %s"
        res = self._execute_sql(sql, (run_id,))
        r = res.fetchone()
        return r
                    
    def get_build_info(self, build_id):
        sql = "SELECT * from builds WHERE build_id = %s"
        res = self._execute_sql(sql, (build_id,))
        build = res.fetchone()
        if build["finished"] is not None and build["started"] is not None:
            build["build_time"] = str(build["finished"] - build["started"])
        try:
            build["stderr"] =  build["stderr"].decode()
        except:
            pass
        try:
            build["stdout"] =  build["stdout"].decode()
        except:
            pass
        run = self.get_data_about_run(build['run_id'])
        build.update(run)
        return build
                    
    def get_histoty_for_base_branch(self, test_id, branch):
        sql = "SELECT name FROM tests WHERE test_id=%s"
        res = self._execute_sql(sql, (test_id,))
        test = res.fetchone()
        history = self.get_test_history(test["name"], branch)
        if len(history):
            test_id_base_branch = history[0]["test_id"]
        else:
            test_id_base_branch = -1
        return {"history": self.history_stats(history), "test_id": test_id_base_branch}
        
    def history_stats(self, history):
        res = {"PASSED": 0, "FAILED": 0, "OTHER": 0}
        for h in history:
            if h["status"] == "PASSED":
                res["PASSED"] += 1
            elif h["status"] == "FAILED" or h["status"] == "BUILD FAILED" or h["status"] == "TIMEOUT":
                res["FAILED"] += 1
            else:
                res["OTHER"] += 1
        return res
        
    def get_one_test(self, test_id):
        sql = "SELECT * FROM tests WHERE test_id=%s"
        res = self._execute_sql(sql, (test_id,))
        tests = res.fetchall()
        for test in tests:
            run_data = self.get_data_about_run(test["run_id"])
            new_data = self.get_data_about_test(test, run_data["branch"], blob=True) 
            test.update(new_data)
            test.update(run_data)       
        return tests
