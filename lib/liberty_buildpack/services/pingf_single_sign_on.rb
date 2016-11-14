# Encoding: utf-8
# IBM WebSphere Application Server Liberty Buildpack
# Copyright 2013 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
require 'rexml/document'
require 'liberty_buildpack/diagnostics/logger_factory'
require 'liberty_buildpack/services/utils'
require 'json'

module LibertyBuildpack::Services

  #------------------------------------------------------------------------------------
  # The Default class is used as the plugin for services that don't provide a plugin.
  # The Default class will attempt to generate cloud variables for the service, and
  # nothing more. This will work if the service has provided "standard" JSON.
  #------------------------------------------------------------------------------------

  class SingleSignOn

    #------------------------------------------------------------------------------------
    # Initialize
    #
    # @param type - the vcap_services type
    # @param config - a hash containing the configuration data from the yml file.
    #------------------------------------------------------------------------------------
    def initialize(type, config)
      @logger = LibertyBuildpack::Diagnostics::LoggerFactory.get_logger
      @type = type
      @features = config['features']
    end

    #-----------------------------------------------------------------------------------------
    # parse the vcap services and create cloud properties
    #
    # @param element - the root element of the REXML document for runtime-vars.xml
    # @param instance - the hash containing the vcap_services data for this instance
    #------------------------------------------------------------------------------------------
    def parse_vcap_services(element, instance)
      @logger.debug('sso - in parse_vcap_services')
      properties = Utils.parse_compliant_vcap_service(element, instance) do |name, value|
        if name == 'credentials.serverSupportedScope' && value.instance_of?(Array)
          value.join(' ')
        else
          value
        end
      end
      @service_name = properties['service_name']
      create_server_xml_vars
    end

    #-----------------------------------------------------------------------------------
    # return true if this service requires Liberty extensions to be installed
    #-----------------------------------------------------------------------------------
    def requires_liberty_extensions?
      false
    end

    #---------------------------------------------
    # Get the list of Liberty features required by this service
    #
    # @param [Set] features - the Set to add the required features to
    #---------------------------------------------
    def get_required_features(features)
      features.merge(@features) unless @features.nil?
    end

    #----------------------------------------------------------------------------------------
    # Use the configured client_jars regular expression to determine which client jars need to be downloaded for this service to function properly
    #
    # @param existing - an array containing the file names of user-provided jars. If the user has provided the jar, no need to download.
    # @param urls - an array containing the available download urls for client jars
    # return - a non-null array of urls. Will be empty if nothing needs to be downloaded.
    #-----------------------------------------------------------------------------------------
    def get_urls_for_client_jars(existing, urls)
      []
    end

    #-------------------------------------------
    # Get required components (prereq zips and esas) from services
    #
    # @param uris - the hash containing the <key, uri> information from the repository
    # @param components - the non-null RequiredComponents to update.
    #---------------------------------------------
    def get_required_esas(uris, components)
      false
    end

    #------------------------------------------------------------------------------------
    # Method to create an openidConnectClient and minimal SSL config (defaultKeyStore) in server.xml.
    #
    # @param doc - the REXML::Document root element for server.xml
    # @param server_dir - the server directory which is the location for bootstrap.properties and jvm.options
    # @param driver_dir - the symbolic name of the directory where client jars are installed
    # @param available_jars - an array containing the names of all installed client driver jars.
    # @raise if a problem was discovered (incoherent or inconsistent existing configuration, for example)
    #------------------------------------------------------------------------------------
    def create(doc, server_dir, driver_dir, available_jars)
      @logger.debug('sso - in create adding features and openidclient')
      Utils.add_features(doc, @features)
      add_oidc(doc)
      add_custom_ssl(doc)
      add_key_store(doc)
      add_web_app_security(doc)
    end

    #------------------------------------------------------------------------------------
    # Method to create/update an openidConnectClient and keyStore stanza in server.xml.
    #
    # If an openidConnectClient stanze with the same id exists, we update it.  Otherwise we add it.
    #
    # openidConnectClient uses the default SSL configuration for the server.  If a default SSL configuration
    # exists, it must contain appropriate trust store certificate to establish a connection with the
    # opendidConnectServer.  If no default SSL configuration exists, we'll add the minimal default SSl
    # configuration which is simply a keystore with id of defaultKeyStore.  It is set up to reference the
    # java default keystore cacerts which contains the necessary cert.
    #
    # @param doc - the REXML::Document root element for server.xml
    # @param server_dir - the server directory which is the location for bootstrap.properties and jvm.options
    # @param driver_dir - the symbolic name of the directory where client jars are installed
    # @param available_jars - an array containing the names of all installed client driver jars.
    # @param number_instances - the number of service instances that update the same service-specific server.xml stanzas
    # @raise if a problem was discovered (incoherent or inconsistent existing configuration, for example)
    #------------------------------------------------------------------------------------
    def update(doc, server_dir, driver_dir, available_jars, number_instances)
      @logger.debug('sso - in update adding features')
      Utils.add_features(doc, @features)
      update_open_id_connect_client(doc)
      update_ssl_config(doc)
      update_keystore_config(doc)
      update_web_application_security(doc)
    end

    private

    #----------------------------------------------------------------------
    # update_open_id_cinnect_client
    # logic to determine updates to the oidc stanza
    # @param doc - the REXML::Document root element for server.xml
    #----------------------------------------------------------------------
    def update_open_id_connect_client(doc)
      oidc = doc.elements.to_a("//openidConnectClient[@id='#{@client_id}']")
      if oidc.empty?
        @logger.debug('sso - update detects no oidc config - add it')
        add_oidc(doc)
      else
        @logger.debug('sso - update detects existing oidc config - update it')
        update_oidc(doc, oidc)
      end
    end

    #----------------------------------------------------------------------
    # add_custom_ssl
    # adds a custom ssl configuration for the sso service.
    # @param doc - the REXML::Document root element for server.xml
    #----------------------------------------------------------------------
    def add_custom_ssl(doc)
      @logger.debug('sso - in add_custom_ssl')
      ssl = REXML::Element.new('ssl', doc.root)
      ssl.add_attribute('id', 'ssoSSLConfig')
      ssl.add_attribute('keyStoreRef', 'ssoKeyStore')
      ssl.add_attribute('trustStoreRef', 'ssoKeyStore')
    end

    #----------------------------------------------------------------------
    # update_ssl_config
    # logic to determine updates to the ssl stanza
    # @param doc - the REXML::Document root element for server.xml
    #----------------------------------------------------------------------
    def update_ssl_config(doc)
      sso_ssl = doc.elements.to_a("//ssl[@id='ssoSSLConfig']")
      if sso_ssl.empty?
        @logger.debug('sso - update detects no custom ssl config - add it')
        add_custom_ssl(doc)
      else
        @logger.debug('sso - update detects custom ssl config - update it')
        update_custom_ssl(doc, sso_ssl)
      end
    end

    #----------------------------------------------------------------------
    # update_keystore_config
    # logic to determine updates to the ssl keystore stanza
    # @param doc - the REXML::Document root element for server.xml
    #----------------------------------------------------------------------
    def update_keystore_config(doc)
      keystore = doc.elements.to_a("//keyStore[@id='ssoKeyStore']")
      if keystore.empty?
        @logger.debug('sso - update detects no ssoKeyStore ssl config - add it')
        add_key_store(doc)
      else
        @logger.debug('sso - update detects ssoKeyStore ssl config - update it')
        update_key_store(doc, keystore)
      end
    end

    #----------------------------------------------------------------------
    # update_web_application_security
    # logic to determine updates to the webAppSecurity stanza
    # @param doc - the REXML::Document root element for server.xml
    #----------------------------------------------------------------------
    def update_web_application_security(doc)
      wasec = doc.elements.to_a('//webAppSecurity')
      if wasec.empty?
        @logger.debug('sso - update detects no webAppSecurity config - add it')
        add_web_app_security(doc)
      else
        srs = doc.elements.to_a('//webAppSecurity[@ssoRequireSSL]')
        if srs.empty?
          @logger.debug('sso - update detects existing webAppSecurity with no ssoRequireSSL - update it')
          update_wasec(doc, wasec)
        end
      end
    end
    
    
    

    #----------------------------------------------------------------------
    # add_oidc
    # adds the openidConnectClient stanza to the server.xml
    # @param doc - the REXML::Document root element for server.xml
    #----------------------------------------------------------------------
    def add_oidc(doc)
      @logger.debug('sso - in add_oidc')
      oidc = REXML::Element.new('openidConnectClient', doc.root)
      oidc.add_attribute('id', @client_id)
      oidc.add_attribute('clientId', @client_id)
      oidc.add_attribute('clientSecret', @client_secret)
      oidc.add_attribute('authorizationEndpointUrl', @auth_url)
      oidc.add_attribute('tokenEndpointUrl', @token_url)
      oidc.add_attribute('redirectToRPHostAndPort', "https://#{@host}")
      oidc.add_attribute('issuerIdentifier', @issuer_identifier)
      oidc.add_attribute('scope', @scope)
    #YD 11102016 start - add PingFederate attributes
      puts '-----> Adding PingFederate openidConnectClient attributes'
      oidc.add_attribute('grantType', @grantType)
      oidc.add_attribute('jwkEndpointUrl', @jwkEndpointUrl)
      oidc.add_attribute('signatureAlgorithm', @signatureAlgorithm)
      oidc.add_attribute('userIdentityToCreateSubject', @userIdentityToCreateSubject)
    #YD 11102016 start - add PingFederate attributes
      oidc.add_attribute('httpsRequired', 'true')
      oidc.add_attribute('sslRef', 'ssoSSLConfig')
    end

    #----------------------------------------------------------------------
    # add_key_store
    # adds the defaultKeyStore which is the minimal SSL configuration
    # when there is no existing default ssl configuration found
    # @param doc - the REXML::Document root element for server.xml
    #----------------------------------------------------------------------
    def add_key_store(doc)
      @logger.debug('sso - in add_key_store')
      ks = REXML::Element.new('keyStore', doc.root)
      ks.add_attribute('id', 'ssoKeyStore')
      ks.add_attribute('password', 'changeit')
      ks.add_attribute('type', 'jks')
      ks.add_attribute('location', '${java.home}/lib/security/cacerts')
    end

    #----------------------------------------------------------------------
    # add_sso_require_ssl
    # adds <webAppSecurity ssoRequireSSL="true" />  to the server.xml
    # @param doc - the REXML::Document root element for server.xml
    #----------------------------------------------------------------------
    def add_web_app_security(doc)
      @logger.debug('sso - in add_web_app_security')
      wasec = REXML::Element.new('webAppSecurity', doc.root)
      wasec.add_attribute('ssoRequireSSL', 'true')
      #YD 11142016 begin - enable app security by default
      #puts '-----> Creating security binding for authenticated-->ALL_AUTHENTICATED_USERS'
      #app = REXML::Element.new('webApplication',doc.root)
      #app.add_attribute('name','myapp')
      #app.add_attribute('location','myapp.war')
      #app.add_attribute('type','war')
      #app-bnd = app.add_element('application-bnd')
      #security-role = app-bnd.add_element('security-role')
      #security-role.add_attribute('id','authenticated')
      #security-role.add_attribute('name', 'authenticated')
      #special-subject = security-role.add_element('special-subject')
      #special-subject.add_attribute('type', 'ALL_AUTHENTICATED_USERS')
      #YD 11142016 end
    end

    #----------------------------------------------------------------------
    # update_oidc
    # updates the openidConnectClient stanza
    # @param doc - the REXML::Document root element for server.xml
    # @param oidc - the openidConnectClient element from the  server.xml
    #----------------------------------------------------------------------
    def update_oidc(doc, oidc)
      @logger.debug('sso - in update_oidc')
      Utils.find_and_update_attribute(oidc, 'id', @client_id)
      Utils.find_and_update_attribute(oidc, 'clientId', @client_id)
      Utils.find_and_update_attribute(oidc, 'clientSecret', @client_secret)
      Utils.find_and_update_attribute(oidc, 'authorizationEndpointUrl', @auth_url)
      Utils.find_and_update_attribute(oidc, 'tokenEndpointUrl', @token_url)
      Utils.find_and_update_attribute(oidc, 'redirectToRPHostAndPort', "https://#{@host}")
      Utils.find_and_update_attribute(oidc, 'issuerIdentifier', @issuer_identifier)
      Utils.find_and_update_attribute(oidc, 'scope', @scope)
    #YD 11102016 start - add PingFederate attributes
    puts '-----> Updating PingFederate openidConnectClient attributes'
      Utils.find_and_update_attribute(oidc, 'grantType', @grantType)
      Utils.find_and_update_attribute(oidc, 'jwkEndpointUrl', @jwkEndpointUrl)
      Utils.find_and_update_attribute(oidc, 'signatureAlgorithm', @signatureAlgorithm)
      Utils.find_and_update_attribute(oidc, 'userIdentityToCreateSubject', @userIdentityToCreateSubject)
    #YD 11102016 start - add PingFederate attributes
      Utils.find_and_update_attribute(oidc, 'httpsRequired', 'true')
      Utils.find_and_update_attribute(oidc, 'sslRef', 'ssoSSLConfig')
    end

    #----------------------------------------------------------------------
    # update_wasec
    # updates the webAppSecurity stanza
    # @param doc - the REXML::Document root element for server.xml
    # @param wasec - the webAppSecurity element from the  server.xml
    #----------------------------------------------------------------------
    def update_wasec(doc, wasec)
      @logger.debug('sso - in update_wasec adding ssoRequireSSL attribute')
      Utils.find_and_update_attribute(wasec, 'ssoRequireSSL', 'true')
    end

    #----------------------------------------------------------------------
    # update_key_store
    # updates the keyStore stanza
    # @param doc - the REXML::Document root element for server.xml
    # @param keystore - the keystore to be updated
    #----------------------------------------------------------------------
    def update_key_store(doc, keystore)
      @logger.debug('sso - in update_key_store updating keyStore attribute')
      Utils.find_and_update_attribute(keystore, 'password', 'changeit')
      Utils.find_and_update_attribute(keystore, 'type', 'jks')
      Utils.find_and_update_attribute(keysotre, 'location', '${java.home}/lib/security/cacerts')
    end

    #----------------------------------------------------------------------
    # update_custom_ssl
    # updates the ssl stanza for the custom ssl config
    # @param doc - the REXML::Document root element for server.xml
    # @param sso_ssl - the keystore to be updated
    #----------------------------------------------------------------------
    def update_custom_ssl(doc, sso_ssl)
      @logger.debug('sso - in update_key_store updating keyStore attribute')
      Utils.find_and_update_attribute(sso_ssl, 'id', 'ssoSSLConfig')
      Utils.find_and_update_attribute(sso_ssl, 'keyStoreRef', 'ssoKeyStore')
      Utils.find_and_update_attribute(sso_ssl, 'trustStoreRef', 'ssoKeyStore')
    end

    #-------------------------------------------
    # Create the instance vars used to update the server.xml
    #---------------------------------------------
    def create_server_xml_vars
      @client_id = "${cloud.services.#{@service_name}.connection.clientId}"
      @client_secret = "${cloud.services.#{@service_name}.connection.secret}"
      @auth_url = "${cloud.services.#{@service_name}.connection.authorizationEndpointUrl}"
      @token_url = "${cloud.services.#{@service_name}.connection.tokenEndpointUrl}"
      @scope = "${cloud.services.#{@service_name}.connection.serverSupportedScope}"
      @issuer_identifier = "${cloud.services.#{@service_name}.connection.issuerIdentifier}"
    #YD 11102016 start - add PingFederate attributes
      puts '-----> Creating PingFederate configuration in server.xml'
      @grantType = "${cloud.services.#{@service_name}.connection.grantType}"
      @jwkEndpointUrl = "${cloud.services.#{@service_name}.connection.jwkEndpointUrl}"
      @signatureAlgorithm = "${cloud.services.#{@service_name}.connection.signatureAlgorithm}"
      @userIdentityToCreateSubject = "${cloud.services.#{@service_name}.connection.userIdentityToCreateSubject}"
    #YD 11102016 end - add PingFederate attributes
      parsed_vcap_app_data = JSON.parse(ENV['VCAP_APPLICATION'])
      @logger.debug("parsed_vcap_app_data is #{parsed_vcap_app_data}")
      @host = parsed_vcap_app_data['uris'][0]
    end

  end
end