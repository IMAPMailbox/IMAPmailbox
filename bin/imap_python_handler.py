import splunk.admin as admin

# -----------------------------------------------
# setup.xml uses this script to update imap.conf
# ----------------------------------------------
class IMAPHandler(admin.MConfigHandler):

  # -------------------------------------------------------
  # set the read / optional arguments for the diff actions
  # -------------------------------------------------------
  def setup(self):
    
    if self.requestedAction in (admin.ACTION_CREATE,):

      self.supportedArgs.addReqArg("server")
      self.supportedArgs.addReqArg("user")
      #actually one of password or xpassword also needs to be provided. But no easy way to do it here. 
      #so we will perform the actual validation for this in the create handler itself 
 
    if self.requestedAction in (admin.ACTION_CREATE,admin.ACTION_EDIT):

#PJ are all of these in imap.conf??
      self.supportedArgs.addOptArg("debug")
      self.supportedArgs.addOptArg("folders")
      self.supportedArgs.addOptArg("fullHeaders")
      self.supportedArgs.addOptArg("imapSearch")
      self.supportedArgs.addOptArg("includeBody")
      self.supportedArgs.addOptArg("mimeTypes")
      self.supportedArgs.addOptArg("noCache")
      self.supportedArgs.addOptArg("password")
      self.supportedArgs.addOptArg("port")
      self.supportedArgs.addOptArg("splunkHostPath")
      self.supportedArgs.addOptArg("splunkpassword")
      self.supportedArgs.addOptArg("splunkuser")
      self.supportedArgs.addOptArg("splunkxpassword")
      self.supportedArgs.addOptArg("timeout")
      self.supportedArgs.addOptArg("useSSL")
      self.supportedArgs.addOptArg("xpassword")

    if self.requestedAction in (admin.ACTION_EDIT,):
      
      self.supportedArgs.addOptArg("server")
      self.supportedArgs.addOptArg("user")

    
  # -------------------------------- 
  # create the imap.conf file
  # --------------------------------
  def handleCreate(self, confInfo):

    settings = self.callerArgs.copy()
    passwdProvided = False

    if 'password' in self.callerArgs.data.keys() and self.callerArgs['password']:
       passwdProvided = True
    elif 'xpassword' in self.callerArgs.data.keys() and self.callerArgs['xpassword']:
       passwdProvided = True

    if not passwdProvided:
       raise admin.ArgValidationException, "Either password or xpassword must be provided"   
     
    self.updateConf("imap", self.callerArgs.id, self.callerArgs.data);
  

  # ---------------------------------------
  # lists out all the configs in imap.conf
  # ---------------------------------------
  def handleList(self, confInfo):

    confDict = self.readConf("imap")
    # if the file doesn't exist, None is returned.
    if None != confDict:
      # return all these settings by populating confInfo.
      for stanza, settings in confDict.items():
        for key, val in settings.items():
          confInfo[stanza].append(key, val)


  # ---------------------------------------
  # removes any config item from imap.conf
  # ---------------------------------------
  def handleRemove(self, confInfo):

    # let's make sure this thing exists, first...
    existing = admin.ConfigInfo()
    self.handleList(existing)
    if not self.callerArgs.id in existing:
      raise admin.ArgValidationException, "Cannot remove '%s', it does not exist." % self.callerArgs.id

    # now that we're sure, set it to disabled and write it out.
    settsDict = self.readConf("imap")[self.callerArgs.id]
    settsDict["disabled"] = "true"
    self.updateConf("imap", self.callerArgs.id, settsDict)
  

  # ----------------------------------- 
  # edits a config item from imap.conf
  # -----------------------------------
  def handleEdit(self, confInfo):

    # let's make sure this thing exists, first...
    existing = admin.ConfigInfo()
    self.handleList(existing)
    if not self.callerArgs.id in existing:
      raise admin.ArgValidationException, "Cannot edit '%s', it does not exist." % self.callerArgs.id

    self.updateConf("imap", self.callerArgs.id, self.callerArgs.data)


admin.init(IMAPHandler, admin.ACTION_CREATE | admin.ACTION_EDIT | admin.ACTION_LIST | admin.ACTION_REMOVE)
