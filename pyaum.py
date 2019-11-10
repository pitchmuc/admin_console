# -*- coding: utf-8 -*-
"""
Created on Wed Jan  2 10:29:45 2019
@author: piccini


This module has been developed in order to help the clients of Adobe solution to manage their users.
This module is a wrapper around the User Management API of Adobe. It will provide help to manage access rights and group management. 

Make sure that you possess the right User Rights and you have established an Adobe IO connection setup before starting this API. 

You can have a complete view of the different method available through this API by going to : datanalyst.info

The different method available : 
    
    createConfigFile(verbose=False) : Create a file to fill all of the required information for the API calls. 
    
    importConfigFile(file) : Import the JSON file with the filled information you have passed. It will populate the different variable with correct information. 
    
    retrievingToken(verbose=False) : retrieve the token for the calls to the API
    
    setEnvironmentTest() : Set test as environment. So you can test the API connection without impacting your production environement. 
    
    retrieveInfos(info='all',fileType='csv',verbose=False) : retrieve the information for your account. It can retrieve 2 type of information (users and groups)
    
    findAdminRoles(df) : Takes the dataframe of users and fill a new column to identify admin
    
    retrieveUserDetail(user,verbose=False) : Retrieve information for only one user. 
    
    createTemplates(fileType='csv',verbose=False) : Create a template to import new users or new groups. 
    
    findProducts(df=None,csvFile=None,xlsxFile=None) : Detect the different product that is enabled for your account. 
    
    getAllGroups(df_groups=None,xlsxFile=None,csvFile=None) : Retrieve all of the groups of your account. 
    
    create_users(usersInformation=None, accessType='adobe' ,verbose=False) : Create the users in your production environment (or just testing this list of users by setting the test environment)

    create_usersGroups(groupsInformation=None, verbose=False) : Create User groups in your production. 
    
    remove_users(usersInformation=None, verbose=False) : Remove the users from groups or from your account.
    
    remove_usersGroups(groupsInformation=None, verbose=False) : Remove group directly in your account. 

"""
import time as _time
import re as _re
from concurrent import futures as _futures
import json as _json
## Non standard libraries
import requests as _requests
import jwt as _jwt
import pandas as _pd
from pathlib import Path as _Path

### Set up default values
_org_id, _api_key, _tech_id, _pathToKey, _secret = "","","","","",
_TokenEndpoint = "https://ims-na1.adobelogin.com/ims/exchange/jwt"
_orga_admin ={'_org_admin','_deployment_admin','_support_admin'}
_cwd = _Path.as_posix(_Path.cwd())
_date_limit = 0
_token = ''

_instances = dict() ## get all the instances created by the groupHandler class

#### User Management Access API
_endpoint = 'https://usermanagement.adobe.io/v2/usermanagement/'
_endpoint_actions = "https://usermanagement.adobe.io/v2/usermanagement/action/"
_limit_print = "The API can only take 10 requests per minute.\nThe API is able to update 10 users per request.\nIf you provide more than the limit, your request will be split."

### GET INFORMATION ABOUT USERS & GROUPS
# + 0 page number (max 200 returned) GET method
_getUsers = 'users/'
_getSingleUser = ''  # when requesting single user info, normally _org_id+'/users/'
_getGroups = 'groups/'  # + 0 page number, requesting groups
_status_codes_errors = [429, 502, 503, 504]

def _updateWithOrgId(orgId):
    global _getUsers
    global _getSingleUser
    global _getGroups
    global _endpoint_actions
    _getUsers += orgId+'/'
    _getSingleUser = orgId+'/users/'  # when requesting single user info
    _getGroups += orgId+'/'  # + 0 page number, requesting groups
    _endpoint_actions += orgId


#### TO DO 
## set token as keyword argument, easier to replace within decorator

#def retrievingToken(org_id,tech_id,api_key,secret,private_key_unencrypted=None):
def retrieveToken(verbose=False):
    """ Retrieve the token by using the information provided by the user during the import importConfigFile function. 
    
    Argument : 
        verbose : OPTIONAL : Default False. If set to True, print information.
    """
#    if private_key_unencrypted == None:
#        raise Exception('private key is required to run this application')
    with open(_pathToKey, 'r') as f:
        private_key_unencrypted = f.read()
        header_jwt = {'cache-control':'no-cache','content-type':'application/x-www-form-urlencoded'}
    jwtPayload = {
        "exp": round(24*60*60+ int(_time.time())),###Expiration set to 24 hours
        "iss": _org_id, ###org_id
        "sub": _tech_id,###technical_account_id
        "https://ims-na1.adobelogin.com/s/ent_user_sdk": True,
        "aud": "https://ims-na1.adobelogin.com/c/"+_api_key
    }
    encoded_jwt = _jwt.encode(jwtPayload, private_key_unencrypted , algorithm='RS256')##working algorithm
    payload = {
            "client_id":_api_key,
            "client_secret":_secret,
            "jwt_token" : encoded_jwt.decode("utf-8")
            }
    response = _requests.post(_TokenEndpoint, headers=header_jwt, data=payload)
    json_response = response.json()
    token = json_response['access_token']
    expire = json_response['expires_in']
    global _date_limit ## getting the scope right
    _date_limit= _time.time()+ expire/1000 -500 ## end of time for the token
    with open('token.txt','w') as f: ##save the token
        f.write(token)
    if verbose == True:
        print('token valid till : ' + _time.ctime(_time.time()+ expire/1000))
        print('token has been saved here : ' + _Path.as_posix(_Path.cwd()))
    return token

def _checkTokenValidity(func):
    """ decorator : Check if the request can be made with the previous token, otherwise give a new token"""
    global _token
    currentTime = _time.time()
    def argumentVerification(*args, token=_token, **kwargs):
        if currentTime-500 > _date_limit:## if actual timestamp higher than date limit
            global _token
            _token = retrieveToken()
            return func(*args,token=_token,**kwargs)
        return func(*args,**kwargs)
    return argumentVerification

def _limitList(myList,limit):
    # For item i in a range that is a length of myList,
    for i in range(0, len(myList), limit):
        # Create an index range for myList of 10 items:
        yield myList[i:i+10]


def createConfigFile(verbose=False):
    """
    This function will create a 'config_admin.json' file where you can store your access data. 
    """
    json_data = {
        'org_id': '<orgID>',
        'api_key': "<APIkey>",
        'tech_id': "<something>@techacct.adobe.com",
        'secret': "<YourSecret>",
        'pathToKey': '<path/to/your/privatekey.key>'
    }
    with open('config_admin.json', 'w') as cf:
        cf.write(_json.dumps(json_data, indent=4))
    if verbose:
        print(' file created at this location : '+_cwd + '/config_admin.json')


def importConfigFile(file):
    """
    This function will read the 'config_admin.json' to retrieve the information to be used by this module. 
    """
    global _org_id
    global _api_key
    global _tech_id
    global _pathToKey
    global _secret
    with open(file, 'r') as file:
        f = _json.load(file)
        _org_id = f['org_id']
        _updateWithOrgId(_org_id)
        _api_key = f['api_key']
        _tech_id = f['tech_id']
        _secret = f['secret']
        _pathToKey = f['pathToKey']
        

def setEnvironmentTest():
    """
    Add the parameter ?testOnly=true to the endpoint.
    It will not apply your modification to your company user or group data base. 
    It is interesting to test your user and group information. 
    
    """
    global _endpoint_actions
    _endpoint_actions += '?testOnly=true'


def _request_users(page,umapi_header):
    """ Taking care of requesting the users info and check if there is an issue"""
    request_users = _requests.get(_endpoint+_getUsers+str(page),headers=umapi_header)
    try_nb = 0
    while request_users.status_code in _status_codes_errors:##Check if we have done too many request in a period of time
        try_nb += 1
        if try_nb<=5:
            print('Issue Retrieving information.\nError Code : '+str(request_users.status_code)+'\nTrying Again in 60s.')
            _time.sleep(60)
            request_users = _requests.get(_endpoint+_getUsers+str(page),headers=umapi_header)
        else:
            request_users = {'lastPage':True,'users':['issue with the API request']}
    request_users_json = request_users.json()
    if request_users_json['result'] != 'success': ## taking care in case problem with setup provided
        request_users = {'lastPage':True,'users':[request_users_json['message']]}
    last_page = request_users_json['lastPage']
    list_users = request_users_json['users']## stack the users
    return list_users, last_page
    
def _request_users_group(page,groupName,umapi_header):
    """ Taking care of requesting the users info and check if there is an issue"""
    request_users = _requests.get(_endpoint+_getUsers+str(page)+'/'+groupName,headers=umapi_header)
    try_nb = 0
    while request_users.status_code in _status_codes_errors:##Check if we have done too many request in a period of time
        if try_nb<=5:
            try_nb += 1
            print('Issue Retrieving information.\nError Code : '+request_users.status_code+'\nTrying Again in 60s.')
            _time.sleep(60)
            request_users = _requests.get(_endpoint+_getUsers+str(page),headers=umapi_header)
        else:
            request_users = {'lastPage':True,'users':['issue with the API request']}
    request_users_json = request_users.json()
    if request_users_json['result'] != 'success': ## taking care in case problem with setup provided
        request_users = {'lastPage':True,'users':[request_users_json['message']]}
    last_page = request_users_json['lastPage']
    list_users = request_users_json['users']## stack the users
    return list_users,last_page

def _request_single_user(userEmail,umapi_header):
    request_users = _requests.get(_endpoint+_getSingleUser+userEmail,headers=umapi_header)
    try_nb = 0
    while request_users.status_code in _status_codes_errors:##Check if we have done too many request in a period of time
        if try_nb<=5:
            try_nb += 1
            print('Issue Retrieving information.\nError Code : '+request_users.status_code+'\nTrying Again in 60s.')
            _time.sleep(60)
            request_users = _requests.get(_endpoint+_getSingleUser+userEmail,headers=umapi_header)
        else:
            request_users = {'lastPage':True,'users':['issue with the API request']}
    request_users_json = request_users.json()
    if request_users_json.text == "":
        return ''
    df =_pd.DataFrame.from_dict(request_users_json,orient='index')
    df = df.T.set_index('id',drop=True)
    return df

def _request_groups(page,umapi_header):
    """ Taking care of requesting the users info and check if there is an issue"""
    request_groups = _requests.get(_endpoint+_getGroups+str(page),headers=umapi_header)
    #print(request_groups.request.url)
    #print(_json.dumps(request_groups.json(),indent=4))
    try_nb = 0
    if request_groups.status_code in _status_codes_errors:##Check if we have done too many request in a period of time
        print('Issue : ' + request_groups.request.url)
        while try_nb<=5 and request_groups.status_code in _status_codes_errors:
            try_nb += 1
            print('Issue Retrieving information.\nError Code : '+str(request_groups.status_code)+'\nTrying Again in 90s.')
            _time.sleep(90)
            request_groups = _requests.get(_endpoint+_getGroups+str(page),headers=umapi_header)
            print('new try : '+str(request_groups.status_code))
    request_groups_json = request_groups.json()
    if 'groups' not in request_groups_json.keys():
        request_groups_json['groups'] = ['issue with the API request']
    if request_groups_json.get('result','success') != 'success': ## taking care in case problem with setup provided
        print(_json.dumps(request_groups_json,indent=4))
        request_groups_json = {'lastPage':True,'groups':[request_groups_json['message']]}
        print('setting lastPage manually to True')
    last_page = request_groups_json['lastPage']
    list_groups = request_groups_json['groups']## stack the users
    return list_groups, last_page

def _users_recursive_request(umapi_header,request_type='users',groupName=None,userEmail=None,last_page=False,page=0):
    full_list_users=[]
    while last_page != True:
        if request_type == 'groups':
            if groupName==None: ## in case no group name has been given
                request_type ='user'
                pass
            else:
                response = _request_users(page, umapi_header)
        elif request_type == 'users':
            response = _request_users(page,umapi_header)
        full_list_users +=response[0]
        last_page = response[1]
        page+=1
    df = _pd.DataFrame(full_list_users)
    df.fillna('',inplace=True)
    return df

def _groups_recursive_request(umapi_header,last_page=False,page=0):
    full_list_groups=[]
    while last_page != True:
        response = _request_groups(page,umapi_header)
        full_list_groups +=response[0]
        last_page = response[1]
        page+=1
    df = _pd.DataFrame(full_list_groups)
    df.fillna('',inplace=True)
    return df

def findAdminRoles(df):
    """ set new attributes for users dataframe. If they are Org Admin or Product Admin 
    Takes dataframe of users and insert new roles.
    """
    admin_regex = _re.compile('.*_admin_(.+?)$')
    df['orgAdmin'] = False
    df['groupAdmin'] = ''
    for index, user in df.iterrows(): 
        if len(set(df.loc[index,'groups']) & _orga_admin)>0:
            df.at[index,'orgAdmin'] = True
        list_admin = [] ##list where the user is an admin
        for group in df.loc[index,'groups']:
            if admin_regex.search(group) != None:
                list_admin.append(admin_regex.search(group).group(1))
        df.at[index,'groupAdmin'] = list_admin

def retrieveInfos(info='all',fileType='csv',verbose=False):
    """ This method retrieves the information abour yours users and your groups in your organization.
    Returns a dictionary that contains dataframe(s): 
    Dictionary keys : 
        - 'users' : for user data
        - 'groups' : for groups data
    Parameters : 
        info : OPTIONAL : Default value 'all', possibles values : 
            "users" : retrict the information retrieved to users only.
            "groups" : retrict the information retrieved to groups only.
            "all" : retrieve users and groups informations.
        fileType : OPTIONAL : Default value 'csv'. Can be 'xlsx' for having excel format
        verbose : OPTIONAL : Default False. If set to True, print information.
    """
    filename = _cwd + '/user_infos.xlsx'
    global _token
    if _token != "" and _date_limit > _time.time()+500 :
        _token = _token
    else : 
        _token = retrieveToken()
    umapi_header = {"Content-type" : "application/json","Accept" : "application/json","x-api-key" : _api_key,"Authorization" : "Bearer " + _token}
    if fileType=='xlsx':
        writer = _pd.ExcelWriter(filename, engine='xlsxwriter')
    data = {}
    if info=='all':
        data['groups']= _groups_recursive_request(umapi_header)
        data['users'] = _users_recursive_request(umapi_header)
        ### Writing info
        if fileType=='xlsx':
            data['users'].to_excel(writer, sheet_name='users_infos',index=False)
            data['groups'].to_excel(writer, sheet_name='groups_infos',index=False)
        else : 
            data['users'].to_csv('users_infos.csv',index=False,sep='\t')
            data['groups'].to_csv('groups_infos.csv',index=False,sep='\t')
    elif info == 'users' :
        data['users'] = _users_recursive_request(umapi_header)
        if fileType=='xlsx':
            data['users'].to_excel(writer, sheet_name='users_infos',index=False)
        else:
            data['users'].to_csv('users_infos.csv',index=False,sep='\t')
    elif info == 'groups':
        data['groups'] = _groups_recursive_request(umapi_header)
        if fileType=='xlsx':
            data['groups'].to_excel(writer, sheet_name='groups_infos',index=False)
        else:
            data['groups'].to_csv('groups_infos.csv',index=False,sep='\t')
    if fileType=='xlsx':
        writer.save()
    if verbose==True:
        print('your file has been created and saved here : '+_cwd)
    return data

def retrieveUserDetail(user,verbose=False):
    """It will retrieve only one user information on this account.
    Returns a single line data frame, the key being the user ID. 
    If user provided in the function is not found, will return an empty string. 
    
    Arguments:
        user : REQUIRED : valid email address to request information. 
        verbose : OPTIONAL : Default False. If set to True, print information.
    
    """
    if '@' not in user:
        raise TypeError('Expecting an email address')
    global _token
    if _token != "" and _date_limit > _time.time()+500 :
        _token = _token
    else : 
        _token = retrieveToken()
    umapi_header = {"Content-type" : "application/json","Accept" : "application/json","x-api-key" : _api_key,"Authorization" : "Bearer " + _token}
    data = _request_single_user(user,umapi_header)
    if data =="" and verbose is True:
        print('no user data found')
    return data

def createTemplates(fileType='csv',verbose=False):
    """ 
    Create template files for user and group details.
    2 types of file can be created, it will be defined by the fileType. 
    fileType : REQUIRED : 2 possible values : 
        - 'csv' : different files in csv format
        - 'xlsx' : one excel file with different format
    verbose : Default False. If set to True, print information.
    """
    df_template_new_user = {'email':['email-address'],'firstname':['OPTIONAL'],'lastname':['OPTIONAL'],'country':['OPTIONAL : Country Code']}
    #df_template_update_user = {'email':['email-address'],'firstname':['OPTIONAL'],'lastname':['OPTIONAL'],'country':['OPTIONAL : Country Code']}
    df_template_new_group = {'name':['group-name'],'description':['OPTIONAL']}
    template_new_users = _pd.DataFrame(df_template_new_user)
    template_new_group = _pd.DataFrame(df_template_new_group)
    if fileType == 'xlsx':
        writer = _pd.ExcelWriter(_cwd +'/template_users_groups.xlsx', engine='xlsxwriter')
        template_new_users.to_excel(writer,sheet_name='new_users',index=False)
        template_new_group.to_excel(writer,sheet_name='new_groups',index=False)
        writer.save()
    elif fileType == 'csv':
        template_new_users.to_csv('new_users.csv', index=False,sep='\t')
        template_new_group.to_csv('new_groups.csv', index=False,sep='\t')
    if verbose==True:
        print('Template Files have been created in : '+ _cwd)

def findProducts(df=None,csvFile=None,xlsxFile=None):
    """ find the products that are attached to this account by screening the groups dataframe.
    It can take any of those parameters, but only one : 
        df : Dataframe of the group information retrieved
        csvFile : csv file that contains the information retrieved. Separator : Tab
        xlsxFile : xlsx file that contains the information retrieved
    returns a list of product
    """
    if df is not None and isinstance(df,_pd.DataFrame) == True:
        df_groups = df
    elif csvFile is not None and 'csv' in csvFile:
        df_groups = _pd.read_excel(csvFile,delimiter='\t')
    elif xlsxFile is not None and 'xlsx' in xlsxFile:
        df_groups = _pd.read_excel(xlsxFile,sheet_name='groups_infos')
    products = set(df_groups['productName'])
    if '' in products:
        products.remove('')
    list_product = list(products)
    return list_product

def getAllGroups(df_groups=None,xlsxFile=None,csvFile=None):
    """ Retrieves all the possible groups from the excel file or csv file
    Returns a list of all groups. 
    Arguments : (one is required)
        - df : dataframe that contains the group information, as retrieved by this module
        - xlsxFile : name of the excel file that has been created by this module and contains the group information
        - csvFile : name of the csv file that has been created by this module and contains the group information. Separator Tab. 
    """
    if df_groups is not None and isinstance(df_groups,_pd.DataFrame) == True:
        df_groups = df_groups.copy()
    elif xlsxFile is not None and 'xlsx' in xlsxFile : 
        df_groups = _pd.read_excel(xlsxFile, sheet_name='groups_infos')
    elif csvFile is not None and 'csv' in csvFile : 
        df_groups = _pd.read_excel(csvFile, delimiter='\t')
    df_groups.fillna('',inplace=True)
    all_groups = set(list(df_groups['adminGroupName']) + list(df_groups['groupName']))
    if '' in all_groups:
        all_groups.remove('')
    return list(all_groups) 

def _createRequest(data):
    global _endpoint_actions
    global _token
    global _api_key
    json_format = _json.dumps(data)
    header =  {"Content-type" : "application/json","Accept" : "application/json","x-api-key" : _api_key,"Authorization" : "Bearer " + _token} 
    res_creation = _requests.post(_endpoint_actions,headers=header,data=json_format)
    res = res_creation.json()
    return res

def create_users(usersInformation=None, accessType='adobe' ,verbose=False):
    """ Send the list of users to Adobe in order to create the users access as Adobe ID.
    At the moment no other user creation is supported.
    Returns the status of the different upload in a list.
    Arguments : 
        - usersInformation : REQUIRED : Dataframe of all the users that need to have access created.
        - accessType : OPTIONAL : default value adobeid, it will create an adobe id.
        possible values : 
            -- adobe : will create an adobe id
            -- enterprise : will create an enterprise id
        - verbose : OPTIONAL : if information of the different request status to be print
    """
    if accessType == 'adobe':
        accessType = 'addAdobeID'
    elif accessType =='enterprise':
        accessType = 'createEnterpriseID'
    if isinstance(usersInformation,_pd.DataFrame) == True:
        list_do = []
        for user in usersInformation.iterrows():
            json = {
                'user':user[1]['email'],
                'do':[{
                    accessType: {
                'email': user[1]['email'],
                'firstname':user[1]['firstname'],
                'lastname':user[1]['lastname'],
                'country':user[1]['country']
                }
                }]
            }
            list_do.append(json)
    elif isinstance(usersInformation,_pd.Series) == True:
        list_do = [{
                'user':usersInformation['email'],
                'do':[{
                    accessType: {
                'email': usersInformation['email'],
                'firstname':usersInformation['firstname'],
                'lastname':usersInformation['lastname'],
                'country':usersInformation['country']
                }
            }]
        }]
    else:
        raise TypeError('UsersInformation should be a dataframe or a series object.')
    global _token
    if _token != "" and _date_limit > _time.time()+500 :
        _token = _token
    else : 
        _token = retrieveToken()
    listOfData = list(_limitList(list_do,10))
    workers = min((len(listOfData),10))
    if verbose:
        print('list of users to create: ' + listOfData )
        print('number of thread created : '+str(workers))
    with _futures.ThreadPoolExecutor(workers) as executor:
        res = executor.map(_createRequest,listOfData) ##return a generator
    responses = list(res)
    return responses

def create_usersGroups(groupsInformation=None, verbose=False):
    """ Send the list of groups to Adobe in order to create the groups.
    Returns the status of the different upload in a list.
    Arguments : 
        - groupsInformation : REQUIRED : Dataframe of all the groups that will be created.
        - verbose : OPTIONAL : if information of the different request status to be print
    """
    if isinstance(groupsInformation,_pd.DataFrame) == True:
        list_do = []
        for group in groupsInformation.iterrows():
            json = {
                'usergroup':group[1]['name'],
                'do':[{'createUserGroup':{
                        'name': group[1]['name'],
                        'description': group[1]['description'],
                        'option': 'updateIfAlreadyExists'
                      }
                }]
            }
            list_do.append(json)
    elif isinstance(groupsInformation,_pd.Series) == True:
        list_do = [{
            'usergroup':groupsInformation['name'],
            'do':[{
                "createUserGroup": {
                    'name': groupsInformation['name'],
                    'description':groupsInformation['description'],
                    'option': 'updateIfAlreadyExists'
                    }
                }]
        }]
    else:
        raise TypeError('UsersInformation should be a dataframe or a series object.')
    global _token
    if _token != "" and _date_limit > _time.time()+500 :
        _token = _token
    else : 
        _token = retrieveToken()
    listOfData = list(_limitList(list_do,10))
    workers = min((len(listOfData),10))
    if verbose:
        print('list of groups to create: ' + listOfData )
        print('number of thread created : '+str(workers))
    with _futures.ThreadPoolExecutor(workers) as executor:
        res = executor.map(_createRequest,listOfData)
    responses = list(res)
    return responses


def remove_users(usersInformation=None, verbose=False):
    """ Remove the user from the organization and all groups.
    If the user account is an enterprise account, it will also be deleted.
    Returns the status of the request
    Arguments : 
        - usersInformation : REQUIRED : Dataframe of all the users that need to be remove from the org.
        If the users are adobe accounts, you cannot delete the access. 
        - verbose : OPTIONAL : if information of the different request status to be print
    """
    if isinstance(usersInformation,_pd.DataFrame) == True:
        list_do = []
        for user in usersInformation.iterrows():
            json = {
                'user':user[1]['email'],
                'do':[{
                    "removeFromOrg": {
                        "deleteAccount": True
                        }
                }]
            }
            list_do.append(json)
    elif isinstance(usersInformation,_pd.Series) == True:
        list_do = [{
                'user':usersInformation['email'],
                'do':[{
                    "removeFromOrg": {
                        "deleteAccount": True
                        }
                }]
        }]
    else:
        raise TypeError('UsersInformation should be a dataframe or a series object.')
    global _token
    if _token != "" and _date_limit > _time.time()+500 :
        _token = _token
    else : 
        _token = retrieveToken()
    listOfData = list(_limitList(list_do,10))
    workers = min((len(listOfData),10))
    if verbose:
        print('list of users to remove: ' + listOfData )
        print('number of thread created : '+str(workers))
    with _futures.ThreadPoolExecutor(workers) as executor:
        res = executor.map(_createRequest,listOfData) ##return a generator
    responses = list(res)
    return responses

def remove_usersGroups(groupsInformation=None, verbose=False):
    """ Send the list of groups to Adobe in order to create the groups.
    Returns the status of the different upload in a list.
    Arguments : 
        - groupsInformation : REQUIRED : Dataframe of all the groups that will be created.
        - verbose : OPTIONAL : if information of the different request status to be print
    """
    if isinstance(groupsInformation,_pd.DataFrame) == True:
        list_do = []
        for group in groupsInformation.iterrows():
            json = {
                'usergroup':group[1]['name'],
                'do':[{
                        "deleteUserGroup": {}
                    }]
            }
            list_do.append(json)
    elif isinstance(groupsInformation,_pd.Series) == True:
        list_do = [{
            'usergroup':groupsInformation['name'],
            'do':[{
                    "deleteUserGroup": {}
                }]
        }]
    else:
        raise TypeError('UsersInformation should be a dataframe or a series object.')
    global _token
    if _token != "" and _date_limit > _time.time()+500 :
        _token = _token
    else : 
        _token = retrieveToken()
    listOfData = list(_limitList(list_do,10))
    workers = min((len(listOfData),10))
    if verbose:
        print('list of groups to remove: ' + listOfData )
        print('number of thread created : '+str(workers))
    with _futures.ThreadPoolExecutor(workers) as executor:
        res = executor.map(_createRequest,listOfData)
    responses = list(res)
    return responses

def generateGroupInstances(df_groups=None,xlsxFile=None,csvFile=None,groupType='all'):
    """ Generates instances of the groupHandler class in order to manage groups.
    Returns 2 elements : the list of the instances created and the dictionnary to call them.
    Arguments : (one is required)
        - df_groups : dataframe containing the the group information, as retrieved by this module
        - xlsxFile : name of the excel file that has been created by this module and contains the group information
        - csvFile : name of the csv file that has been created by this module and contains the group information. Separator Tab. 
        - groupType : Focus on a specific group type on this generation. The different options are : 
            -- user_group : groups created by the company.
            -- user_admin_group : admin groups of user_groups.
            -- product_profile : product profile groups. The one giving custom access to a product. 
            -- profile_admin_group : admin groups for the product_profile groups.
            -- product_admin_group : admin groups for the products. Bind to a product.
            -- sysadmin_group : super admin group
            -- developer_group : developer group. Access to APIs of Adobe IO.
            -- all : all groups (default)
    """
    if df_groups is not None and isinstance(df_groups,_pd.DataFrame) == True:
        df_groups = df_groups
    elif xlsxFile is not None and 'xlsx' in xlsxFile : 
        df_groups = _pd.read_excel(xlsxFile, sheet_name='groups_infos')
    elif csvFile is not None and 'csv' in csvFile : 
        df_groups = _pd.read_csv(csvFile, delimiter='\t')
    df_groups.fillna('',inplace=True)
    if groupType == 'all':
        all_groups = set(list(df_groups['adminGroupName']) + list(df_groups['groupName']))
        if '' in all_groups: all_groups.remove('')
    elif groupType == 'user_group':
        all_groups = list(df_groups[df_groups['type']==groupType.upper()]['groupName'])
    elif groupType == 'user_admin_group':## group not present in Groupname if no user inside
        all_groups = list(df_groups[df_groups['type']=='USER_GROUP']['adminGroupName'])
    elif groupType == 'product_profile':
        all_groups = list(df_groups[df_groups['type']==groupType.upper()]['groupName'])
    elif groupType == 'profile_admin_group':## group not present in Groupname if no user inside
        all_groups = list(df_groups[df_groups['type']=='PRODUCT_PROFILE']['adminGroupName'])
    elif groupType == 'product_admin_group':
        all_groups = list(df_groups[df_groups['type']==groupType.upper()]['groupName'])
    elif groupType == 'sysadmin_group':
        all_groups = list(df_groups[df_groups['type']==groupType.upper()]['groupName'])
    elif groupType == 'developer_group':
        all_groups = list(df_groups[df_groups['type']==groupType.upper()]['groupName'])
    list_groups = list(all_groups)
    func_dict = {} #specific dict for this creation
    global _instances #keep track of created instances on global scope.
    for group in list_groups:
        group_str = str(group)
        inst = groupHandler(group)
        _instances[group_str] = inst
        func_dict[group_str] = inst
    return list(func_dict.keys()), func_dict

class groupHandler:
    """ Class to handle your group one by one. Takes 1 argument to initiate the group name, can take an additional argument to initiate some users in the group
    Arguments : 
        - groupName : REQUIRED : name of the group (string)
        - users : OPTIONAL : Could be one user (string) or list of users (list or tuple)
    Users has to be added by email address.

    class objects : 
        - new_users : Users that you added using the addUser method or by creating the instance.
        - delete_users : Users that you want to remove. Added by using the method removeUsers.
        - users = users that have been added to the group and send to the Admin platform. They have been processed.
        - new_productProfile : Product Profile(s) you want to add to the group.
        - remove_productProfile : Product Profile(s) you want to delete from the group.
        - productProfile : Product Profile(s) you have on this group
    """

    groupName = ''
    response = '' 
    def __init__(self, groupName, users=None):
        self.new_users = []
        self.delete_users = []
        self.users = []
        self.groupName = groupName
        ## product profile not supported by Adobe API at the moment
        #self.new_productProfile = []
        #self.remove_productProfile = []
        #self.productProfile = []
        if users != None:
            if type(users) is str:
                users = users.split(' ')
            self.new_users += users

    def addUsers(self,users=None):
        """ Take a list or tuple of users emails and assigned it to the dimension new_users """
        if users is not None:
            if type(users) is str:
                    users = users.split(' ')
            for user in users: 
                if user not in self.users and user not in self.new_users:
                    self.new_users.append(user)
                else:
                    print('User ('+str(user)+') already exists in this group.')
    
    def _addExistingUsers(self,users=None):
        """ Take a list or tuple of users emails and assigned it to the group of existing users"""
        if users is not None:
            if type(users) is str:
                    users = users.split(' ')
            self.users += users
            self.users = list(set(self.users))

    def removeUsers(self,users=None):
        """ Take iterable of users and assigned it to the variable of "delete_users" for deleted them later on """
        if users is not None:
            if type(users) is str:
                    users = users.split(' ')
            for name in users : 
                if name in self.users : self.users.remove(name)
                if name in self.new_users : self.new_users.remove(name)
                self.delete_users.append(name)

    def fill_users(self,df_users=None):
        """
        Fill the list of users based on the user dataframe retrieved from the "retrieveInfos" function of this module. 
        
        Fill the internal the "users" variable and returns the list. 
        """
        if isinstance(df_users,_pd.DataFrame) is False: 
            raise TypeError('Expected a dataframe as df_users')
        for _, row in df_users.iterrows():
            if type(row['groups']) is str:
                multi_groups = row['groups'][1:-1].replace("'","").split(', ') #clean the string before creating the list
            elif type(row['groups']) is list:
                multi_groups = df_users.loc[3]['groups']
            if self.groupName in multi_groups:
                self._addExistingUsers(row['email'])
        return self.users
        
    
    if '_admin_' not in groupName:
        def createAdminGroup(self):
            return groupHandler("_admin_"+self.groupName)
    
    @_checkTokenValidity
    def syncGroup(self,action='add',token=_token):
        """ Method to update the group information on the Adobe server.
        Arguments : 
            action : REQUIRED : possible actions : 
                - add : default : will take the users in the new_users variable and send them to adobe. 
                Make sure that those users already have an Adobe account.
                - remove : will take the users in the delete_users variable and send them to adobe.
                Those users won't be part of the group later on. 
            
            token : OPTIONAL : if you have generated the token manually, can take the value. 
            
        returns the list of the response the server is giving back.
        
        """
        if action == 'add':
            newlist_users = list(self.new_users)
        elif action == 'remove':
            newlist_users = list(self.delete_users)
        list_response = []
        group = str(self.groupName)
        list_json = list()
        for user in newlist_users:## will generate list from generator
            json = [{
                'user':str(user),
                'do':[{
                    str(action): {
                        "group": [str(group)]
                        }
                }]
            }]
            list_json.append(json)
        workers = min((len(newlist_users),10))
        with _futures.ThreadPoolExecutor(workers) as executor:
            res = executor.map(_createRequest,list_json)
        list_response = list(res)
        if action == 'add':
            self._addExistingUsers(self.new_users)
            self.new_users = []
        elif action == 'remove':
            self.delete_users = []
        return list_response
