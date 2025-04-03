#!/bin/bash
mkdir mattermost 
echo "password" | sudo -S chmod -R 777 mattermost
cd mattermost

touch .env
cat > .env <<EOF
# Domain of service
DOMAIN=localhost

# Container settings
## Timezone inside the containers. The value needs to be in the form 'Europe/Berlin'.
## A list of these tz database names can be looked up at Wikipedia
## https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
TZ=UTC
RESTART_POLICY=unless-stopped

# Postgres settings
## Documentation for this image and available settings can be found on hub.docker.com
## https://hub.docker.com/_/postgres
## Please keep in mind this will create a superuser and it's recommended to use a less privileged
## user to connect to the database.
## A guide on how to change the database user to a nonsuperuser can be found in docs/creation-of-nonsuperuser.md
POSTGRES_IMAGE_TAG=13-alpine
POSTGRES_DATA_PATH=./volumes/db/var/lib/postgresql/data

POSTGRES_USER=mmuser
POSTGRES_PASSWORD=mmuser_password
POSTGRES_DB=mattermost

# Nginx
## The nginx container will use a configuration found at the NGINX_MATTERMOST_CONFIG. The config aims
## to be secure and uses a catch-all server vhost which will work out-of-the-box. For additional settings
## or changes ones can edit it or provide another config. Important note: inside the container, nginx sources
## every config file inside */etc/nginx/conf.d* ending with a *.conf* file extension.

## Inside the container the uid and gid is 101. The folder owner can be set with
## `sudo chown -R 101:101 ./nginx` if needed.
## Note that this repository requires nginx version 1.25.1 or later
NGINX_IMAGE_TAG=alpine

## The folder containing server blocks and any additional config to nginx.conf
NGINX_CONFIG_PATH=./nginx/conf.d
NGINX_DHPARAMS_FILE=./nginx/dhparams4096.pem

CERT_PATH=./volumes/web/cert/cert.pem
KEY_PATH=./volumes/web/cert/key-no-password.pem
#GITLAB_PKI_CHAIN_PATH=<path_to_your_gitlab_pki>/pki_chain.pem
#CERT_PATH=./certs/etc/letsencrypt/live/${DOMAIN}/fullchain.pem
#KEY_PATH=./certs/etc/letsencrypt/live/${DOMAIN}/privkey.pem

## Exposed ports to the host. Inside the container 80, 443 and 8443 will be used
HTTPS_PORT=443
HTTP_PORT=80
CALLS_PORT=8443

# Mattermost settings
## Inside the container the uid and gid is 2000. The folder owner can be set with
## `sudo chown -R 2000:2000 ./volumes/app/mattermost`.
MATTERMOST_CONFIG_PATH=./volumes/app/mattermost/config
MATTERMOST_DATA_PATH=./volumes/app/mattermost/data
MATTERMOST_LOGS_PATH=./volumes/app/mattermost/logs
MATTERMOST_PLUGINS_PATH=./volumes/app/mattermost/plugins
MATTERMOST_CLIENT_PLUGINS_PATH=./volumes/app/mattermost/client/plugins
MATTERMOST_BLEVE_INDEXES_PATH=./volumes/app/mattermost/bleve-indexes

## Bleve index (inside the container)
MM_BLEVESETTINGS_INDEXDIR=/mattermost/bleve-indexes

## This will be 'mattermost-enterprise-edition' or 'mattermost-team-edition' based on the version of Mattermost you're installing.
MATTERMOST_IMAGE=mattermost-enterprise-edition
## Update the image tag if you want to upgrade your Mattermost version. You may also upgrade to the latest one. The example is based on the latest Mattermost ESR version.
MATTERMOST_IMAGE_TAG=latest

## Make Mattermost container readonly. This interferes with the regeneration of root.html inside the container. Only use
## it if you know what you're doing.
## See https://github.com/mattermost/docker/issues/18
MATTERMOST_CONTAINER_READONLY=false

## The app port is only relevant for using Mattermost without the nginx container as reverse proxy. This is not meant
## to be used with the internal HTTP server exposed but rather in case one wants to host several services on one host
## or for using it behind another existing reverse proxy.
APP_PORT=8065

## Configuration settings for Mattermost. Documentation on the variables and the settings itself can be found at
## https://docs.mattermost.com/administration/config-settings.html
## Keep in mind that variables set here will take precedence over the same setting in config.json. This includes
## the system console as well and settings set with env variables will be greyed out.

## Below one can find necessary settings to spin up the Mattermost container
MM_SQLSETTINGS_DRIVERNAME=postgres
MM_SQLSETTINGS_DATASOURCE=postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}?sslmode=disable&connect_timeout=10

## Example settings (any additional setting added here also needs to be introduced in the docker-compose.yml)
MM_SERVICESETTINGS_SITEURL=http://${DOMAIN}:8065/
EOF

touch compose.yml
cat > compose.yml <<EOF
# https://docs.docker.com/compose/environment-variables/
services:
  postgres:
    image: msai-cn-beijing.cr.volces.com/agent/postgres:${POSTGRES_IMAGE_TAG}
    restart: ${RESTART_POLICY}
    security_opt:
      - no-new-privileges:true
    pids_limit: 100
    read_only: true
    tmpfs:
      - /tmp
      - /var/run/postgresql
    volumes:
      - ${POSTGRES_DATA_PATH}:/var/lib/postgresql/data
    environment:
      # timezone inside container
      - TZ

      # necessary Postgres options/variables
      - POSTGRES_USER
      - POSTGRES_PASSWORD
      - POSTGRES_DB

  mattermost:
    depends_on:
      - postgres
    image: msai-cn-beijing.cr.volces.com/agent/mattermost:${MATTERMOST_IMAGE_TAG}
    ports:
      - ${APP_PORT}:8065
      - ${CALLS_PORT}:${CALLS_PORT}/udp
      - ${CALLS_PORT}:${CALLS_PORT}/tcp
    restart: ${RESTART_POLICY}
    security_opt:
      - no-new-privileges:true
    pids_limit: 200
    read_only: ${MATTERMOST_CONTAINER_READONLY}
    tmpfs:
      - /tmp
    volumes:
      - ${MATTERMOST_CONFIG_PATH}:/mattermost/config:rw
      - ${MATTERMOST_DATA_PATH}:/mattermost/data:rw
      - ${MATTERMOST_LOGS_PATH}:/mattermost/logs:rw
      - ${MATTERMOST_PLUGINS_PATH}:/mattermost/plugins:rw
      - ${MATTERMOST_CLIENT_PLUGINS_PATH}:/mattermost/client/plugins:rw
      - ${MATTERMOST_BLEVE_INDEXES_PATH}:/mattermost/bleve-indexes:rw
      # When you want to use SSO with GitLab, you have to add the cert pki chain of GitLab inside Alpine
      # to avoid Token request failed: certificate signed by unknown authority 
      # (link: https://github.com/mattermost/mattermost-server/issues/13059 and https://github.com/mattermost/docker/issues/34)
      # - ${GITLAB_PKI_CHAIN_PATH}:/etc/ssl/certs/pki_chain.pem:ro
    environment:
      # timezone inside container
      - TZ

      # necessary Mattermost options/variables (see env.example)
      - MM_SQLSETTINGS_DRIVERNAME
      - MM_SQLSETTINGS_DATASOURCE

      # necessary for bleve
      - MM_BLEVESETTINGS_INDEXDIR

      # additional settings
      - MM_SERVICESETTINGS_SITEURL
EOF

mkdir -p ./volumes/app/mattermost/{config,data,logs,plugins,client/plugins,bleve-indexes}
echo "password" | sudo -S chown -R 2000:2000 ./volumes/app/mattermost
echo "password" | sudo -S chmod -R 777 ./volumes/app/mattermost


cat > ./volumes/app/mattermost/config/config.json <<EOF
{
    "ServiceSettings": {
        "SiteURL": "",
        "WebsocketURL": "",
        "LicenseFileLocation": "",
        "ListenAddress": ":8065",
        "ConnectionSecurity": "",
        "TLSCertFile": "",
        "TLSKeyFile": "",
        "TLSMinVer": "1.2",
        "TLSStrictTransport": false,
        "TLSStrictTransportMaxAge": 63072000,
        "TLSOverwriteCiphers": [],
        "UseLetsEncrypt": false,
        "LetsEncryptCertificateCacheFile": "./config/letsencrypt.cache",
        "Forward80To443": false,
        "TrustedProxyIPHeader": [],
        "ReadTimeout": 300,
        "WriteTimeout": 300,
        "IdleTimeout": 60,
        "MaximumLoginAttempts": 10,
        "GoroutineHealthThreshold": -1,
        "EnableOAuthServiceProvider": true,
        "EnableIncomingWebhooks": true,
        "EnableOutgoingWebhooks": true,
        "EnableOutgoingOAuthConnections": false,
        "EnableCommands": true,
        "OutgoingIntegrationRequestsTimeout": 30,
        "EnablePostUsernameOverride": false,
        "EnablePostIconOverride": false,
        "GoogleDeveloperKey": "",
        "EnableLinkPreviews": true,
        "EnablePermalinkPreviews": true,
        "RestrictLinkPreviews": "",
        "EnableTesting": false,
        "EnableDeveloper": false,
        "DeveloperFlags": "",
        "EnableClientPerformanceDebugging": false,
        "EnableOpenTracing": false,
        "EnableSecurityFixAlert": true,
        "EnableInsecureOutgoingConnections": false,
        "AllowedUntrustedInternalConnections": "",
        "EnableMultifactorAuthentication": false,
        "EnforceMultifactorAuthentication": false,
        "EnableUserAccessTokens": false,
        "AllowCorsFrom": "",
        "CorsExposedHeaders": "",
        "CorsAllowCredentials": false,
        "CorsDebug": false,
        "AllowCookiesForSubdomains": false,
        "ExtendSessionLengthWithActivity": false,
        "TerminateSessionsOnPasswordChange": false,
        "SessionLengthWebInDays": 100000,
        "SessionLengthWebInHours": 2400000,
        "SessionLengthMobileInDays": 100000,
        "SessionLengthMobileInHours": 2400000,
        "SessionLengthSSOInDays": 100000,
        "SessionLengthSSOInHours": 2400000,
        "SessionCacheInMinutes": 10,
        "SessionIdleTimeoutInMinutes": 43200,
        "WebsocketSecurePort": 443,
        "WebsocketPort": 80,
        "WebserverMode": "gzip",
        "EnableGifPicker": true,
        "GiphySdkKey": "",
        "EnableCustomEmoji": true,
        "EnableEmojiPicker": true,
        "PostEditTimeLimit": -1,
        "TimeBetweenUserTypingUpdatesMilliseconds": 5000,
        "EnablePostSearch": true,
        "EnableFileSearch": true,
        "MinimumHashtagLength": 3,
        "EnableUserTypingMessages": true,
        "EnableChannelViewedMessages": true,
        "EnableUserStatuses": true,
        "ExperimentalEnableAuthenticationTransfer": true,
        "ClusterLogTimeoutMilliseconds": 2000,
        "EnablePreviewFeatures": true,
        "EnableTutorial": true,
        "EnableOnboardingFlow": true,
        "ExperimentalEnableDefaultChannelLeaveJoinMessages": true,
        "ExperimentalGroupUnreadChannels": "disabled",
        "EnableAPITeamDeletion": false,
        "EnableAPITriggerAdminNotifications": false,
        "EnableAPIUserDeletion": false,
        "ExperimentalEnableHardenedMode": false,
        "ExperimentalStrictCSRFEnforcement": false,
        "EnableEmailInvitations": true,
        "DisableBotsWhenOwnerIsDeactivated": true,
        "EnableBotAccountCreation": false,
        "EnableSVGs": true,
        "EnableLatex": true,
        "EnableInlineLatex": true,
        "PostPriority": true,
        "AllowPersistentNotifications": true,
        "AllowPersistentNotificationsForGuests": false,
        "PersistentNotificationIntervalMinutes": 5,
        "PersistentNotificationMaxCount": 6,
        "PersistentNotificationMaxRecipients": 5,
        "EnableAPIChannelDeletion": false,
        "EnableLocalMode": false,
        "LocalModeSocketLocation": "/var/tmp/mattermost_local.socket",
        "EnableAWSMetering": false,
        "SplitKey": "",
        "FeatureFlagSyncIntervalSeconds": 30,
        "DebugSplit": false,
        "ThreadAutoFollow": true,
        "CollapsedThreads": "always_on",
        "ManagedResourcePaths": "",
        "EnableCustomGroups": true,
        "AllowSyncedDrafts": true,
        "UniqueEmojiReactionLimitPerPost": 50,
        "RefreshPostStatsRunTime": "00:00",
        "MaximumPayloadSizeBytes": 300000
    },
    "TeamSettings": {
        "SiteName": "Mattermost",
        "MaxUsersPerTeam": 50,
        "EnableJoinLeaveMessageByDefault": true,
        "EnableUserCreation": true,
        "EnableOpenServer": false,
        "EnableUserDeactivation": false,
        "RestrictCreationToDomains": "",
        "EnableCustomUserStatuses": true,
        "EnableCustomBrand": false,
        "CustomBrandText": "",
        "CustomDescriptionText": "",
        "RestrictDirectMessage": "any",
        "EnableLastActiveTime": true,
        "UserStatusAwayTimeout": 300,
        "MaxChannelsPerTeam": 2000,
        "MaxNotificationsPerChannel": 1000,
        "EnableConfirmNotificationsToChannel": true,
        "TeammateNameDisplay": "username",
        "ExperimentalViewArchivedChannels": true,
        "ExperimentalEnableAutomaticReplies": false,
        "LockTeammateNameDisplay": false,
        "ExperimentalPrimaryTeam": "",
        "ExperimentalDefaultChannels": []
    },
    "ClientRequirements": {
        "AndroidLatestVersion": "",
        "AndroidMinVersion": "",
        "IosLatestVersion": "",
        "IosMinVersion": ""
    },
    "SqlSettings": {
        "DriverName": "postgres",
        "DataSource": "postgres://mmuser:mostest@localhost/mattermost_test?sslmode=disable\u0026connect_timeout=10\u0026binary_parameters=yes",
        "DataSourceReplicas": [],
        "DataSourceSearchReplicas": [],
        "MaxIdleConns": 20,
        "ConnMaxLifetimeMilliseconds": 3600000,
        "ConnMaxIdleTimeMilliseconds": 300000,
        "MaxOpenConns": 300,
        "Trace": false,
        "AtRestEncryptKey": "nfroo5zyannh6y48b3ww3qrwck6a4akn",
        "QueryTimeout": 30,
        "DisableDatabaseSearch": false,
        "MigrationsStatementTimeoutSeconds": 100000,
        "ReplicaLagSettings": [],
        "ReplicaMonitorIntervalSeconds": 5
    },
    "LogSettings": {
        "EnableConsole": true,
        "ConsoleLevel": "DEBUG",
        "ConsoleJson": true,
        "EnableColor": false,
        "EnableFile": true,
        "FileLevel": "INFO",
        "FileJson": true,
        "FileLocation": "",
        "EnableWebhookDebugging": true,
        "EnableDiagnostics": true,
        "VerboseDiagnostics": false,
        "EnableSentry": true,
        "AdvancedLoggingJSON": {},
        "AdvancedLoggingConfig": "",
        "MaxFieldSize": 2048
    },
    "ExperimentalAuditSettings": {
        "FileEnabled": false,
        "FileName": "",
        "FileMaxSizeMB": 100,
        "FileMaxAgeDays": 0,
        "FileMaxBackups": 0,
        "FileCompress": false,
        "FileMaxQueueSize": 1000,
        "AdvancedLoggingJSON": {},
        "AdvancedLoggingConfig": ""
    },
    "NotificationLogSettings": {
        "EnableConsole": true,
        "ConsoleLevel": "DEBUG",
        "ConsoleJson": true,
        "EnableColor": false,
        "EnableFile": true,
        "FileLevel": "INFO",
        "FileJson": true,
        "FileLocation": "",
        "AdvancedLoggingJSON": {},
        "AdvancedLoggingConfig": ""
    },
    "PasswordSettings": {
        "MinimumLength": 8,
        "Lowercase": false,
        "Number": false,
        "Uppercase": false,
        "Symbol": false,
        "EnableForgotLink": true
    },
    "FileSettings": {
        "EnableFileAttachments": true,
        "EnableMobileUpload": true,
        "EnableMobileDownload": true,
        "MaxFileSize": 104857600,
        "MaxImageResolution": 33177600,
        "MaxImageDecoderConcurrency": -1,
        "DriverName": "local",
        "Directory": "./data/",
        "EnablePublicLink": false,
        "ExtractContent": true,
        "ArchiveRecursion": false,
        "PublicLinkSalt": "3ad3ge4g8nr6gxmmipjhtixas3k184h5",
        "InitialFont": "nunito-bold.ttf",
        "AmazonS3AccessKeyId": "",
        "AmazonS3SecretAccessKey": "",
        "AmazonS3Bucket": "",
        "AmazonS3PathPrefix": "",
        "AmazonS3Region": "",
        "AmazonS3Endpoint": "s3.amazonaws.com",
        "AmazonS3SSL": true,
        "AmazonS3SignV2": false,
        "AmazonS3SSE": false,
        "AmazonS3Trace": false,
        "AmazonS3RequestTimeoutMilliseconds": 30000,
        "AmazonS3UploadPartSizeBytes": 5242880,
        "DedicatedExportStore": false,
        "ExportDriverName": "local",
        "ExportDirectory": "./data/",
        "ExportAmazonS3AccessKeyId": "",
        "ExportAmazonS3SecretAccessKey": "",
        "ExportAmazonS3Bucket": "",
        "ExportAmazonS3PathPrefix": "",
        "ExportAmazonS3Region": "",
        "ExportAmazonS3Endpoint": "s3.amazonaws.com",
        "ExportAmazonS3SSL": true,
        "ExportAmazonS3SignV2": false,
        "ExportAmazonS3SSE": false,
        "ExportAmazonS3Trace": false,
        "ExportAmazonS3RequestTimeoutMilliseconds": 30000,
        "ExportAmazonS3PresignExpiresSeconds": 21600,
        "ExportAmazonS3UploadPartSizeBytes": 104857600
    },
    "EmailSettings": {
        "EnableSignUpWithEmail": true,
        "EnableSignInWithEmail": true,
        "EnableSignInWithUsername": true,
        "SendEmailNotifications": true,
        "UseChannelInEmailNotifications": false,
        "RequireEmailVerification": false,
        "FeedbackName": "",
        "FeedbackEmail": "test@example.com",
        "ReplyToAddress": "test@example.com",
        "FeedbackOrganization": "",
        "EnableSMTPAuth": false,
        "SMTPUsername": "",
        "SMTPPassword": "",
        "SMTPServer": "localhost",
        "SMTPPort": "10025",
        "SMTPServerTimeout": 10,
        "ConnectionSecurity": "",
        "SendPushNotifications": false,
        "PushNotificationServer": "",
        "PushNotificationContents": "full",
        "PushNotificationBuffer": 1000,
        "EnableEmailBatching": false,
        "EmailBatchingBufferSize": 256,
        "EmailBatchingInterval": 30,
        "EnablePreviewModeBanner": true,
        "SkipServerCertificateVerification": false,
        "EmailNotificationContentsType": "full",
        "LoginButtonColor": "#0000",
        "LoginButtonBorderColor": "#2389D7",
        "LoginButtonTextColor": "#2389D7"
    },
    "RateLimitSettings": {
        "Enable": false,
        "PerSec": 10,
        "MaxBurst": 100,
        "MemoryStoreSize": 10000,
        "VaryByRemoteAddr": true,
        "VaryByUser": false,
        "VaryByHeader": ""
    },
    "PrivacySettings": {
        "ShowEmailAddress": true,
        "ShowFullName": true
    },
    "SupportSettings": {
        "TermsOfServiceLink": "https://mattermost.com/pl/terms-of-use/",
        "PrivacyPolicyLink": "https://mattermost.com/pl/privacy-policy/",
        "AboutLink": "https://mattermost.com/pl/about-mattermost",
        "HelpLink": "https://mattermost.com/pl/help/",
        "ReportAProblemLink": "https://mattermost.com/pl/report-a-bug",
        "ForgotPasswordLink": "",
        "SupportEmail": "",
        "CustomTermsOfServiceEnabled": false,
        "CustomTermsOfServiceReAcceptancePeriod": 365,
        "EnableAskCommunityLink": true
    },
    "AnnouncementSettings": {
        "EnableBanner": false,
        "BannerText": "",
        "BannerColor": "#f2a93b",
        "BannerTextColor": "#333333",
        "AllowBannerDismissal": true,
        "AdminNoticesEnabled": true,
        "UserNoticesEnabled": true,
        "NoticesURL": "https://notices.mattermost.com/",
        "NoticesFetchFrequency": 3600,
        "NoticesSkipCache": false
    },
    "ThemeSettings": {
        "EnableThemeSelection": true,
        "DefaultTheme": "default",
        "AllowCustomThemes": true,
        "AllowedThemes": []
    },
    "GitLabSettings": {
        "Enable": false,
        "Secret": "",
        "Id": "",
        "Scope": "",
        "AuthEndpoint": "",
        "TokenEndpoint": "",
        "UserAPIEndpoint": "",
        "DiscoveryEndpoint": "",
        "ButtonText": "",
        "ButtonColor": ""
    },
    "GoogleSettings": {
        "Enable": false,
        "Secret": "",
        "Id": "",
        "Scope": "profile email",
        "AuthEndpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "TokenEndpoint": "https://www.googleapis.com/oauth2/v4/token",
        "UserAPIEndpoint": "https://people.googleapis.com/v1/people/me?personFields=names,emailAddresses,nicknames,metadata",
        "DiscoveryEndpoint": "",
        "ButtonText": "",
        "ButtonColor": ""
    },
    "Office365Settings": {
        "Enable": false,
        "Secret": "",
        "Id": "",
        "Scope": "User.Read",
        "AuthEndpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "TokenEndpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "UserAPIEndpoint": "https://graph.microsoft.com/v1.0/me",
        "DiscoveryEndpoint": "",
        "DirectoryId": ""
    },
    "OpenIdSettings": {
        "Enable": false,
        "Secret": "",
        "Id": "",
        "Scope": "profile openid email",
        "AuthEndpoint": "",
        "TokenEndpoint": "",
        "UserAPIEndpoint": "",
        "DiscoveryEndpoint": "",
        "ButtonText": "",
        "ButtonColor": "#145DBF"
    },
    "LdapSettings": {
        "Enable": false,
        "EnableSync": false,
        "LdapServer": "",
        "LdapPort": 389,
        "ConnectionSecurity": "",
        "BaseDN": "",
        "BindUsername": "",
        "BindPassword": "",
        "UserFilter": "",
        "GroupFilter": "",
        "GuestFilter": "",
        "EnableAdminFilter": false,
        "AdminFilter": "",
        "GroupDisplayNameAttribute": "",
        "GroupIdAttribute": "",
        "FirstNameAttribute": "",
        "LastNameAttribute": "",
        "EmailAttribute": "",
        "UsernameAttribute": "",
        "NicknameAttribute": "",
        "IdAttribute": "",
        "PositionAttribute": "",
        "LoginIdAttribute": "",
        "PictureAttribute": "",
        "SyncIntervalMinutes": 60,
        "SkipCertificateVerification": false,
        "PublicCertificateFile": "",
        "PrivateKeyFile": "",
        "QueryTimeout": 60,
        "MaxPageSize": 0,
        "LoginFieldName": "",
        "LoginButtonColor": "#0000",
        "LoginButtonBorderColor": "#2389D7",
        "LoginButtonTextColor": "#2389D7",
        "Trace": false
    },
    "ComplianceSettings": {
        "Enable": false,
        "Directory": "./data/",
        "EnableDaily": false,
        "BatchSize": 30000
    },
    "LocalizationSettings": {
        "DefaultServerLocale": "en",
        "DefaultClientLocale": "en",
        "AvailableLocales": ""
    },
    "SamlSettings": {
        "Enable": false,
        "EnableSyncWithLdap": false,
        "EnableSyncWithLdapIncludeAuth": false,
        "IgnoreGuestsLdapSync": false,
        "Verify": true,
        "Encrypt": true,
        "SignRequest": false,
        "IdpURL": "",
        "IdpDescriptorURL": "",
        "IdpMetadataURL": "",
        "ServiceProviderIdentifier": "",
        "AssertionConsumerServiceURL": "",
        "SignatureAlgorithm": "RSAwithSHA1",
        "CanonicalAlgorithm": "Canonical1.0",
        "ScopingIDPProviderId": "",
        "ScopingIDPName": "",
        "IdpCertificateFile": "",
        "PublicCertificateFile": "",
        "PrivateKeyFile": "",
        "IdAttribute": "",
        "GuestAttribute": "",
        "EnableAdminAttribute": false,
        "AdminAttribute": "",
        "FirstNameAttribute": "",
        "LastNameAttribute": "",
        "EmailAttribute": "",
        "UsernameAttribute": "",
        "NicknameAttribute": "",
        "LocaleAttribute": "",
        "PositionAttribute": "",
        "LoginButtonText": "SAML",
        "LoginButtonColor": "#34a28b",
        "LoginButtonBorderColor": "#2389D7",
        "LoginButtonTextColor": "#ffffff"
    },
    "NativeAppSettings": {
        "AppCustomURLSchemes": [
            "mmauth://",
            "mmauthbeta://"
        ],
        "AppDownloadLink": "https://mattermost.com/pl/download-apps",
        "AndroidAppDownloadLink": "https://mattermost.com/pl/android-app/",
        "IosAppDownloadLink": "https://mattermost.com/pl/ios-app/",
        "MobileExternalBrowser": false
    },
    "ClusterSettings": {
        "Enable": false,
        "ClusterName": "",
        "OverrideHostname": "",
        "NetworkInterface": "",
        "BindAddress": "",
        "AdvertiseAddress": "",
        "UseIPAddress": true,
        "EnableGossipCompression": true,
        "EnableExperimentalGossipEncryption": false,
        "ReadOnlyConfig": true,
        "GossipPort": 8074
    },
    "MetricsSettings": {
        "Enable": false,
        "BlockProfileRate": 0,
        "ListenAddress": ":8067",
        "EnableClientMetrics": true,
        "EnableNotificationMetrics": true
    },
    "ExperimentalSettings": {
        "ClientSideCertEnable": false,
        "ClientSideCertCheck": "secondary",
        "LinkMetadataTimeoutMilliseconds": 5000,
        "RestrictSystemAdmin": false,
        "EnableSharedChannels": false,
        "EnableRemoteClusterService": false,
        "DisableAppBar": false,
        "DisableRefetchingOnBrowserFocus": false,
        "DelayChannelAutocomplete": false,
        "DisableWakeUpReconnectHandler": false,
        "UsersStatusAndProfileFetchingPollIntervalMilliseconds": 3000
    },
    "AnalyticsSettings": {
        "MaxUsersForStatistics": 2500
    },
    "ElasticsearchSettings": {
        "ConnectionURL": "http://localhost:9200",
        "Backend": "elasticsearch",
        "Username": "elastic",
        "Password": "changeme",
        "EnableIndexing": false,
        "EnableSearching": false,
        "EnableAutocomplete": false,
        "Sniff": true,
        "PostIndexReplicas": 1,
        "PostIndexShards": 1,
        "ChannelIndexReplicas": 1,
        "ChannelIndexShards": 1,
        "UserIndexReplicas": 1,
        "UserIndexShards": 1,
        "AggregatePostsAfterDays": 365,
        "PostsAggregatorJobStartTime": "03:00",
        "IndexPrefix": "",
        "LiveIndexingBatchSize": 1,
        "BatchSize": 10000,
        "RequestTimeoutSeconds": 30,
        "SkipTLSVerification": false,
        "CA": "",
        "ClientCert": "",
        "ClientKey": "",
        "Trace": "",
        "IgnoredPurgeIndexes": ""
    },
    "BleveSettings": {
        "IndexDir": "",
        "EnableIndexing": false,
        "EnableSearching": false,
        "EnableAutocomplete": false,
        "BatchSize": 10000
    },
    "DataRetentionSettings": {
        "EnableMessageDeletion": false,
        "EnableFileDeletion": false,
        "EnableBoardsDeletion": false,
        "MessageRetentionDays": 365,
        "MessageRetentionHours": 0,
        "FileRetentionDays": 365,
        "FileRetentionHours": 0,
        "BoardsRetentionDays": 365,
        "DeletionJobStartTime": "02:00",
        "BatchSize": 3000,
        "TimeBetweenBatchesMilliseconds": 100,
        "RetentionIdsBatchSize": 100
    },
    "MessageExportSettings": {
        "EnableExport": false,
        "ExportFormat": "actiance",
        "DailyRunTime": "01:00",
        "ExportFromTimestamp": 0,
        "BatchSize": 10000,
        "DownloadExportResults": false,
        "GlobalRelaySettings": {
            "CustomerType": "A9",
            "SMTPUsername": "",
            "SMTPPassword": "",
            "EmailAddress": "",
            "SMTPServerTimeout": 1800,
            "CustomSMTPServerName": "",
            "CustomSMTPPort": "25"
        }
    },
    "JobSettings": {
        "RunJobs": true,
        "RunScheduler": true,
        "CleanupJobsThresholdDays": -1,
        "CleanupConfigThresholdDays": -1
    },
    "ProductSettings": {},
    "PluginSettings": {
        "Enable": true,
        "EnableUploads": false,
        "AllowInsecureDownloadURL": false,
        "EnableHealthCheck": true,
        "Directory": "./plugins",
        "ClientDirectory": "./client/plugins",
        "Plugins": {
            "playbooks": {
                "BotUserID": "af14o9mx7ibkukwhwg84nsqmea"
            }
        },
        "PluginStates": {
            "com.mattermost.calls": {
                "Enable": true
            },
            "com.mattermost.nps": {
                "Enable": true
            },
            "playbooks": {
                "Enable": true
            }
        },
        "EnableMarketplace": true,
        "EnableRemoteMarketplace": true,
        "AutomaticPrepackagedPlugins": true,
        "RequirePluginSignature": false,
        "MarketplaceURL": "https://api.integrations.mattermost.com",
        "SignaturePublicKeyFiles": [],
        "ChimeraOAuthProxyURL": ""
    },
    "DisplaySettings": {
        "CustomURLSchemes": [],
        "MaxMarkdownNodes": 0
    },
    "GuestAccountsSettings": {
        "Enable": false,
        "HideTags": false,
        "AllowEmailAccounts": true,
        "EnforceMultifactorAuthentication": false,
        "RestrictCreationToDomains": ""
    },
    "ImageProxySettings": {
        "Enable": false,
        "ImageProxyType": "local",
        "RemoteImageProxyURL": "",
        "RemoteImageProxyOptions": ""
    },
    "CloudSettings": {
        "CWSURL": "https://customers.mattermost.com",
        "CWSAPIURL": "https://portal.internal.prod.cloud.mattermost.com",
        "CWSMock": false,
        "Disable": false
    },
    "ImportSettings": {
        "Directory": "./import",
        "RetentionDays": 30
    },
    "ExportSettings": {
        "Directory": "./export",
        "RetentionDays": 30
    },
    "WranglerSettings": {
        "PermittedWranglerRoles": [],
        "AllowedEmailDomain": [],
        "MoveThreadMaxCount": 100,
        "MoveThreadToAnotherTeamEnable": false,
        "MoveThreadFromPrivateChannelEnable": false,
        "MoveThreadFromDirectMessageChannelEnable": false,
        "MoveThreadFromGroupMessageChannelEnable": false
    }
}
EOF