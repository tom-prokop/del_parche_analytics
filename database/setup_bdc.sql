/*** Network Policies ***/
use role SECURITYADMIN;

create or replace network policy BROOKLYN_DATA_CO
    allowed_ip_list = (
        /* Primary VPN (vpn.brooklyndata.co) */
        '3.15.92.136'
        /* Europe/Middle East/Africa VPN (vpn.eu-west-2.brooklyndata.co) */
        , '18.135.177.95'
        /* Asia-Pacific VPN (vpn.ap-southeast-2.brooklyndata.co) */
        , '54.253.114.16'
        /* US-only VPN (vpn.us-gov-east-1.brooklyndata.co) */
        , '18.252.47.9'
        /* US Chicago 1 (p81-us.brooklyndata.co) */
        , '131.226.36.184'
        /* US New Jersey (p81-us.brooklyndata.co) */
        , '149.28.42.71'
        /* US Silicon Valley (p81-us.brooklyndata.co) */
        , '64.226.128.7'
        /* Non-US Sydney 1 (p81.brooklyndata.co) */
        , '207.148.87.32'
        /* Non-US London (p81.brooklyndata.co) */
        , '209.35.224.240'
        /* Non-US Miami (p81.brooklyndata.co) */
        , '45.77.92.179'
        /* Non-US Chicago 2 (p81.brooklyndata.co) */
        , '144.202.63.27'
    );


/*** Admin Users ***/
use role ACCOUNTADMIN;

call ADMIN.UTILS.CREATE_ADMIN_USER('NANDO_ADMIN', 'ACCOUNTADMIN', 'nando @ Brooklyn Data Co.');
    alter user NANDO_ADMIN set
        network_policy = 'BROOKLYN_DATA_CO'
        email          = 'hernandoconeo1@hotmail.com'
        display_name   = 'dpc::NANDO_ADMIN';


/*** Analytics Developer Users ***/
use role USERADMIN;

call ADMIN.UTILS.CREATE_NORMAL_USER('NANDO', 'ANALYTICS_DEVELOPER', 'nando @ Brooklyn Data Co.');
    use role SECURITYADMIN;
    alter user NANDO set
        network_policy = 'BROOKLYN_DATA_CO'
        display_name   = 'dpc::NANDO';
    use role USERADMIN;
