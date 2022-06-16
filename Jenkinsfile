pipeline{
  agent any

  stages{
    
    stage("build"){
      
      steps{
        echo 'building the application...'
        echo 'application builds'
      }
    }
    
    stage("test"){
    
      steps{
        echo 'testing the application...'
      }
    }
    
    
    stage('cat README'){
      when {
        branch "new-*"
      }
    }
    
     stage("deploy"){
    
      steps{
        echo 'deploy the application...'
      }
    }
  
  }
}
