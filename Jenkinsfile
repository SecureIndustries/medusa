pipeline {
    agent none
    stages {
        stage('Build') {
            agent {label 'debian'}
            steps {
                sh '''make MEDUSA_BUILD_TEST=n'''
            }
        }
        stage('Test') {
            agent {label 'debian'}
            steps {
                sh '''make MEDUSA_BUILD_TEST=y'''
            }
        }
    }
}