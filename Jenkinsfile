pipeline {
    agent any
    environment { 
        PYTHON = 'sudo /root/.cache/pypoetry/virtualenvs/atf-platform-x-l6ONKZ-py3.8/bin/python3'
        PROJECT = 'ddi2'
        TESTSUITE= 'testsuite_debug'
        LEVEL = 'DEBUG'
    }
    stages {
        stage('执行测试') {
            steps {
                sh '${PYTHON} main.py -p ${PROJECT} -ts ${TESTSUITE} -level ${LEVEL}'
            }
        }
    }
    post ('后置任务') {
    always {
            junit 'reports/junit-reports.xml'
            allure includeProperties: false,
            jdk: '',
            results: [[path: 'reports/allure-results']]
        }
    }
}