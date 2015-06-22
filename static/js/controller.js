angular.module('dropzone', []).directive('dropzone', function () {
  return function (scope, element, attrs) {
    var dropzone, config;
 
    config = scope[attrs.dropzone];
 
    // create a Dropzone for the element with the given options
    dropzone = new Dropzone(element[0], config.options);
 
    // bind the given event handlers
    angular.forEach(config.eventHandlers, function (handler, event) {
      dropzone.on(event, handler);
    });
  };
});

var gaeApp = angular.module('gaeApp', ['dropzone']);

gaeApp.controller('dzCtrl', function ($scope, $http) {
  $scope.dropzoneConfig = {
    'options': { // passed into the Dropzone constructor
      'url': '/upload_photo'
    },
    'eventHandlers': {
      'sending': function (file, xhr, formData) {
  
      },
      'success': function (file, response) {
      }
    }
  };
});
 
gaeApp.controller('formActionController', function($rootScope,$scope, $http){
    $rootScope.authenticated = isAuthenticated;
    $rootScope.username  = fullName;
    $scope.regData = {};
    $scope.logData = {};
    $scope.messageCss = "success";
    $scope.messageType = "Success"
    $scope.register = function(){
    $scope.message = "";
        $http({
            method  : 'POST',
            url     : '/register',
            data    : $.param($scope.regData),  // pass in data as strings
            headers : { 'Content-Type': 'application/x-www-form-urlencoded' }  // set the headers so angular passing info as form data (not request payload)
        }).success(function(data){
            $scope.message =  data.success;
            console.log(data);
        }).error(function(data){
            $scope.messageType = "Error";
            $scope.messageCss =  "danger";
            $scope.message =  data.error;
            console.log(data);
        });
    }
$scope.login = function(){
    $scope.message = "";
        $http({
            method  : 'POST',
            url     : '/login',
            data    : $.param($scope.logData),  // pass in data as strings
            headers : { 'Content-Type': 'application/x-www-form-urlencoded' }  // set the headers so angular passing info as form data (not request payload)
        }).success(function(data){
            $rootScope.authenticated = true;
            $rootScope.username = data.name;
            console.log(data);
        }).error(function(data){
            $scope.messageType = "Error";
            $scope.messageCss =  "danger";
            $scope.message =  data.error;
            $rootScope.authenticated = false;
            console.log(data);
        });
        
    }
});
gaeApp.controller('divActionController', function($rootScope, $scope, $http){
    $rootScope.userPic = userPic;
    $scope.messages = {};
    $scope.users = {};
    $scope.userCount = 0;
    $scope.messageCount = 0;
    if($rootScope.authenticated){
        $http({
            method  : 'GET',
            url     : '/users'
        }).success(function(data){
            console.log(data);
            $scope.users = data.data;
            $scope.userCount = data.data.length;
        });
    $http({
            method  : 'GET',
            url     : '/messages'
        }).success(function(data){
            console.log(data);
            $scope.messages = data.data;
            $scope.messageCount = data.data.length;
        });
    }
    $scope.messageForm = false;
    $scope.viewMessage = false;
    $scope.messageData = {};
    $scope.messageDetail = {};
    $scope.showMessageForm = function(email){
        $scope.messageData.to = email;
        $scope.messageForm  = true;
    }
    $scope.messageDetail = function(message){
        $scope.messageDetail.from = message.sender;
        $scope.messageDetail.title = message.title;
        $scope.messageDetail.content = message.message;
        $scope.viewMessage  = true;
    }
    $scope.cancelMessage = function(){
        //$scope.messageData = {};
        $scope.messageForm = false;
    }
    $scope.closeMessage = function(){
       // $scope.messageDetail = {};
        $scope.viewMessage = false;
    }
    $scope.sendMessage = function(){
        $http({
            method  : 'POST',
            url     : '/messages',
            data    : $.param($scope.messageData),  // pass in data as strings
            headers : { 'Content-Type': 'application/x-www-form-urlencoded' }  // set the headers so angular passing info as form data (not request payload)
        }).success(function(data){
            console.log(data);
            $rootScope.messageForm = false;
        });
        
    }
    $scope.logout = function(){
        $http({
            method  : 'GET',
            url     : '/logout'
        }).success(function(data){
            $rootScope.authenticated = false;
            $rootScope.username = "";
            $rootScope.userPic = "";
        });
    }
    
});
