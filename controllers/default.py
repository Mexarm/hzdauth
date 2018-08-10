# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------
# This is a sample controller
# this file is released under public domain and you can use without limitations
# -------------------------------------------------------------------------

# ---- example index page ----
def index():
    if auth.user:
        tenant = db(db.tenant.id == auth.user.tenant).select(limitby=(0,1)).first()
        return dict( user = auth.user, tenant = tenant)
    return dict()

# ---- API (example) -----
@auth.requires_login()
def api_get_user_email():
    if not request.env.request_method == 'GET': raise HTTP(403)
    return response.json({'status':'success', 'email':auth.user.email})

# ---- Smart Grid (example) -----
@auth.requires_membership('admin') # can only be accessed by members of admin groupd
def grid():
    response.view = 'generic.json' # use a generic view
    tablename = request.args(0)
    if not tablename in db.tables: raise HTTP(403)
    grid = SQLFORM.smartgrid(db[tablename], args=[tablename], deletable=False, editable=False)
    return dict(grid=grid)

# ---- enpoint called by backend server to send a lost password email to the end user
def verifyuser():
    from basicauth import decode
    response.view= 'generic.json'
    #return response.toolbar()
    auth_header= request.env.HTTP_AUTHORIZATION
    if not auth_header: raise HTTP(400) #bad request
    body = request.post_vars
    if not request.env.CONTENT_TYPE == "application/json": raise HTTP(400) # bad request
    username = body['username'] if 'username' in body else False
    if not username: raise HTTP(400) #bad request
    user, apikey = decode(auth_header)
    #return dict(user = user, apikey=apikey)
    if user <> 'api': raise HTTP(401) # not authorized
    tenant = db(db.tenant.apikey == apikey).select(limitby=(0,1)).first()
    if not tenant: raise HTTP(401) # not authorized
    #this is a valid request
    dbuser = db(db.auth_user.email == username).select(limitby=(0,1)).first()
    if not dbuser: raise HTTP(404) #user does no exist
    #send email to user
    if not auth.email_reset_password(dbuser): raise HTTP(500) ## email not sent
    return dict( message = "email enviado" )

auth.settings.allow_basic_login = True
@auth.requires_login()
#@request.restful()
def login():
    response.view = 'generic.json'
    tenant = db(db.tenant.id == auth.user.tenant).select(limitby=(0,1)).first()
    memberships = db(db.auth_membership.user_id == auth.user.id).select()
    roles = []
    for m in memberships:
        roles.append(m.group_id.role)
    claims = dict( roles = roles, email = auth.user.email )
    if tenant:
        claims['tenant'] = tenant.tenant
    return dict( claims = claims )


# ---- Action for login/register/etc (required for auth) -----
def user():
    """
    exposes:
    http://..../[app]/default/user/login
    http://..../[app]/default/user/logout
    http://..../[app]/default/user/register
                                   request_reset_password
    http://..../[app]/default/user/profile
    http://..../[app]/default/user/change_password
    http://..../[app]/default/user/bulk_register
    use @auth.requires_login()
        @auth.requires_membership('group name')
        @auth.requires_permission('read','table name',record_id)
    to decorate functions that need access control
    also notice there is http://..../[app]/appadmin/manage/auth to allow administrator to manage users
    """
    # restringe solo a admin el alta de usuarios.
    #if request.args[0] == "register":
        #if auth.user and auth.has_membership(role='admin'):
            #return dict(form=auth())
        #else:
            #response.flash = 'you are not allowed to register new users'
            #redirect(URL('index'))
    return dict(form=auth())


# ---- action to server uploaded static content (required) ---
#@cache.action()
#def download():
    #"""
    #allows downloading of uploaded files
    #http://..../[app]/default/download/[filename]
    #"""
    #return response.download(request, db)
