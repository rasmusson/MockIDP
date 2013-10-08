MockIDP
=======

MockIDP is a small java web application that supports mocking of a simple SAML IDP.

As of now it o supports SSO through HTTP artifact resolve.

The IDP is not fully SAML compliant and should only be used for testing.

There are two configuration files. 

The metadata file in MockIDP.properties and sp-metadata.xml

MockIDP.properties hold two properties
spEntityId - The ID that identifies your SP in the sp-matedata.xml file
spMetadataLocation - The location of the sp-matedata.xml file

sp-metadata.xml is a standard metadata file that is provided from the user.
This file can typically be exported from the product that is used.

Running the IDP
===============

Running with maven from source
=======================

maven jetty plugin is configured to start up a jetty server with the application at port 9000

The application is started by using mvn jetty:run

Deploying on a webserver
=======================

The application is released as a war file that can be deployed in any java servlet container.


