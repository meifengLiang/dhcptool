pipeline {
    agent any
    environment { 
        PYTHON = '/root/.venv/bin/activate'
    }
    stages {
        stage('执行打包') {
            steps {
                sh '. ${PYTHON}'
                sh '/root/.venv/bin/pyinstaller -F main.py'
                sh 'mv ./dist/main ./dist/dhcptool'
            }
        }
    }
    post ('后置任务') {
    always {
            echo '打包完成'
            echo '下载: http://42.192.146.185:8080/job/dhcptool/4/execution/node/3/ws/dist/dhcptool'
        }
    }
}