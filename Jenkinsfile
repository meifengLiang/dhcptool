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
            }
        }
    }
    post ('后置任务') {
    always {
            echo '打包完成'
        }
    }
}