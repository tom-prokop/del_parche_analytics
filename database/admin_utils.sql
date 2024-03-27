
use role ACCOUNTADMIN;


create database if not exists ADMIN
    comment = 'For admins.';

    create schema if not exists ADMIN.UTILS
        comment = 'For admin utility procedures.';

    drop schema if exists ADMIN.PUBLIC;

grant usage on database ADMIN to role SYSADMIN;
grant usage on database ADMIN to role SECURITYADMIN;
grant usage on database ADMIN to role USERADMIN;

grant usage on schema ADMIN.UTILS to role SYSADMIN;
grant usage on schema ADMIN.UTILS to role SECURITYADMIN;
grant usage on schema ADMIN.UTILS to role USERADMIN;


create or replace procedure ADMIN.UTILS.CREATE_ROLE(ROLE varchar, DESCRIPTION varchar)
    returns varchar
    language sql
    comment = 'Creates the specified role and grants it to the SYSADMIN role.'
    execute as owner
    as $$
        begin
            create role if not exists identifier(:ROLE);
            alter role identifier(:ROLE) set comment = :DESCRIPTION;
            grant role identifier(:ROLE) to role SYSADMIN;

            return 'Created role ' || :ROLE;
        end;
    $$;

    grant ownership on procedure ADMIN.UTILS.CREATE_ROLE(varchar, varchar) to role USERADMIN;
    grant usage     on procedure ADMIN.UTILS.CREATE_ROLE(varchar, varchar) to role SYSADMIN;


create or replace procedure ADMIN.UTILS.GRANT_ALL_IN_DATABASE(DATABASE varchar, ROLE varchar)
    returns varchar
    language sql
    comment = 'Grants all privileges on all existing and future objects within the database to the role.'
    execute as owner
    as $$
        begin
            grant usage, create schema on database identifier(:DATABASE) to role identifier(:ROLE);

            grant all on all    schemas in database identifier(:DATABASE) to role identifier(:ROLE);
            grant all on future schemas in database identifier(:DATABASE) to role identifier(:ROLE);

            grant all on all    tables in database identifier(:DATABASE) to role identifier(:ROLE);
            grant all on future tables in database identifier(:DATABASE) to role identifier(:ROLE);

            grant all on all    views in database identifier(:DATABASE) to role identifier(:ROLE);
            grant all on future views in database identifier(:DATABASE) to role identifier(:ROLE);

            grant all on all    materialized views in database identifier(:DATABASE) to role identifier(:ROLE);
            grant all on future materialized views in database identifier(:DATABASE) to role identifier(:ROLE);

            grant all on all    stages in database identifier(:DATABASE) to role identifier(:ROLE);
            grant all on future stages in database identifier(:DATABASE) to role identifier(:ROLE);

            grant all on all    file formats in database identifier(:DATABASE) to role identifier(:ROLE);
            grant all on future file formats in database identifier(:DATABASE) to role identifier(:ROLE);

            grant all on all    streams in database identifier(:DATABASE) to role identifier(:ROLE);
            grant all on future streams in database identifier(:DATABASE) to role identifier(:ROLE);

            return 'Granted all in database ' || :DATABASE || ' to role ' || :ROLE;
        end;
    $$;

    grant ownership on procedure ADMIN.UTILS.GRANT_ALL_IN_DATABASE(varchar, varchar) to role SECURITYADMIN;
    grant usage     on procedure ADMIN.UTILS.GRANT_ALL_IN_DATABASE(varchar, varchar) to role SYSADMIN;


create or replace procedure ADMIN.UTILS.GRANT_SELECT_IN_DATABASE(DATABASE varchar, ROLE varchar)
    returns varchar
    language sql
    comment = 'Grants select privileges on all existing and future tables/views within the database to the role.'
    execute as owner
    as $$
        begin
            grant select on all    tables in database identifier(:DATABASE) to role identifier(:ROLE);
            grant select on future tables in database identifier(:DATABASE) to role identifier(:ROLE);

            grant select on all    views in database identifier(:DATABASE) to role identifier(:ROLE);
            grant select on future views in database identifier(:DATABASE) to role identifier(:ROLE);

            grant select on all    materialized views in database identifier(:DATABASE) to role identifier(:ROLE);
            grant select on future materialized views in database identifier(:DATABASE) to role identifier(:ROLE);

            return 'Granted select in database ' || :DATABASE || ' to role ' || :ROLE;
        end;
    $$;

    grant ownership on procedure ADMIN.UTILS.GRANT_SELECT_IN_DATABASE(varchar, varchar) to role SECURITYADMIN;
    grant usage     on procedure ADMIN.UTILS.GRANT_SELECT_IN_DATABASE(varchar, varchar) to role SYSADMIN;


create or replace procedure ADMIN.UTILS.GRANT_USAGE_ON_ALL_SCHEMAS_IN_DATABASE(DATABASE varchar, ROLE varchar)
    returns varchar
    language sql
    comment = 'Grants usage privileges on the database and all existing and future schemas within it to the role.'
    execute as owner
    as $$
        begin
            grant usage on database identifier(:DATABASE) to role identifier(:ROLE);

            grant usage on all    schemas in database identifier(:DATABASE) to role identifier(:ROLE);
            grant usage on future schemas in database identifier(:DATABASE) to role identifier(:ROLE);

            return 'Granted usage on database ' || :DATABASE || ' and all its schemas to role ' || :ROLE;
        end;
    $$;

    grant ownership on procedure ADMIN.UTILS.GRANT_USAGE_ON_ALL_SCHEMAS_IN_DATABASE(varchar, varchar) to role SECURITYADMIN;
    grant usage     on procedure ADMIN.UTILS.GRANT_USAGE_ON_ALL_SCHEMAS_IN_DATABASE(varchar, varchar) to role SYSADMIN;


create or replace procedure ADMIN.UTILS.GRANT_USAGE_ON_DATABASE_SCHEMA(DATABASE varchar, SCHEMA varchar, ROLE varchar)
    returns varchar
    language sql
    comment = 'Grants usage privileges on the database and schema to the role.'
    execute as owner
    as $$
        declare QUALIFIED_SCHEMA varchar := DATABASE || '.' || SCHEMA;
        begin
            grant usage on database identifier(:DATABASE) to role identifier(:ROLE);

            grant usage on schema identifier(:QUALIFIED_SCHEMA) to role identifier(:ROLE);

            return 'Granted usage on database ' || :DATABASE || ' and schema ' || :QUALIFIED_SCHEMA || ' to role ' || :ROLE;
        end;
    $$;

    grant ownership on procedure ADMIN.UTILS.GRANT_USAGE_ON_DATABASE_SCHEMA(varchar, varchar, varchar) to role SECURITYADMIN;
    grant usage     on procedure ADMIN.UTILS.GRANT_USAGE_ON_DATABASE_SCHEMA(varchar, varchar, varchar) to role SYSADMIN;


create or replace procedure ADMIN.UTILS.CREATE_DATABASE(DATABASE varchar, DESCRIPTION varchar)
    returns varchar
    language sql
    comment = 'Creates the specified database and associated reader and writer roles.'
    execute as caller
    as $$
        declare
            CALLER_ROLE varchar := CURRENT_ROLE();
            READER_ROLE varchar := DATABASE || '_DB_READER';
            READER_DESCRIPTION varchar := 'Read-only access to entire ' || DATABASE || ' database.';
            WRITER_ROLE varchar := DATABASE || '_DB_WRITER';
            WRITER_DESCRIPTION varchar := 'Full access to entire ' || DATABASE || ' database.';
        begin
            use role SYSADMIN;

            create database if not exists identifier(:DATABASE);
            alter database identifier(:DATABASE) set comment = :DESCRIPTION;

            call ADMIN.UTILS.CREATE_ROLE(:READER_ROLE, :READER_DESCRIPTION);
            call ADMIN.UTILS.CREATE_ROLE(:WRITER_ROLE, :WRITER_DESCRIPTION);

            /* Read access will be controlled at the schema level. */
            call ADMIN.UTILS.GRANT_SELECT_IN_DATABASE(:DATABASE, 'PUBLIC');
            call ADMIN.UTILS.GRANT_USAGE_ON_ALL_SCHEMAS_IN_DATABASE(:DATABASE, :READER_ROLE);

            call ADMIN.UTILS.GRANT_ALL_IN_DATABASE(:DATABASE, :WRITER_ROLE);

            use role identifier(:CALLER_ROLE);

            return 'Created database ' || :DATABASE || ' and associated ' || :READER_ROLE || ' and ' || :WRITER_ROLE || ' roles';
        end;
    $$;

    grant usage on procedure ADMIN.UTILS.CREATE_DATABASE(varchar, varchar) to role SYSADMIN;

create or replace procedure ADMIN.UTILS.CREATE_DATABASE_FROM_SHARE(SHARE varchar, DATABASE varchar, DESCRIPTION varchar)
    returns varchar
    language sql
    comment = 'Creates the specified shared database and associated reader role.'
    execute as owner
    as $$
        declare
            READER_ROLE varchar := DATABASE || '_DB_READER';
            READER_DESCRIPTION varchar := 'Read-only access to entire ' || DATABASE || '.';
            CREATE_DB_QUERY varchar := 'create database if not exists ' || DATABASE || ' from share ' || SHARE;
        begin
            execute immediate :CREATE_DB_QUERY;
            alter database identifier(:DATABASE) set comment = :DESCRIPTION;

            call ADMIN.UTILS.CREATE_ROLE(:READER_ROLE, :READER_DESCRIPTION);

            grant imported privileges on database identifier(:DATABASE) to role identifier(:READER_ROLE);

            return 'Created database ' || :DATABASE || ' and the reader role ' || :READER_ROLE || ' from the share ' || :SHARE;
        end
    $$;

    grant usage on procedure ADMIN.UTILS.CREATE_DATABASE_FROM_SHARE(varchar, varchar, varchar) to role SYSADMIN;


create or replace procedure ADMIN.UTILS.CREATE_DATABASE_SCHEMA(DATABASE varchar, SCHEMA varchar, DESCRIPTION varchar)
    returns varchar
    language sql
    comment = 'Creates the specified database schema and associated reader role.'
    execute as caller
    as $$
        declare
            CALLER_ROLE varchar := CURRENT_ROLE();
            QUALIFIED_SCHEMA varchar := DATABASE || '.' || SCHEMA;
            READER_ROLE varchar := DATABASE || '_' || SCHEMA || '_SCHEMA_READER';
            READER_DESCRIPTION varchar := 'Read-only access to entire ' || QUALIFIED_SCHEMA || ' schema.';
        begin
            use role SYSADMIN;

            create schema if not exists identifier(:QUALIFIED_SCHEMA);
            alter schema identifier(:QUALIFIED_SCHEMA) set comment = :DESCRIPTION;

            call ADMIN.UTILS.CREATE_ROLE(:READER_ROLE, :READER_DESCRIPTION);

            call ADMIN.UTILS.GRANT_USAGE_ON_DATABASE_SCHEMA(:DATABASE, :SCHEMA, :READER_ROLE);

            use role identifier(:CALLER_ROLE);

            return 'Created schema ' || :QUALIFIED_SCHEMA || ' and associated ' || :READER_ROLE || ' role';
        end;
    $$;

    grant usage on procedure ADMIN.UTILS.CREATE_DATABASE_SCHEMA(varchar, varchar, varchar) to role SYSADMIN;


create or replace procedure ADMIN.UTILS.CREATE_WAREHOUSE(WAREHOUSE varchar, DESCRIPTION varchar, USAGE_ROLES array)
    returns varchar
    language sql
    comment = 'Creates the specified warehouse with usage granted to the specified roles.'
    execute as caller
    as $$
        declare
            CALLER_ROLE varchar := CURRENT_ROLE();
            /* By default, Snowflake sets the new warehouse to active so we switch back to the original manually */
            CALLER_WAREHOUSE varchar := current_warehouse();
            ARRAY_LENGTH int := array_size(USAGE_ROLES) - 1;
            CURRENT_ROLE varchar;
        begin
            use role sysadmin;
            create warehouse if not exists identifier(:WAREHOUSE) warehouse_size=xsmall auto_suspend=60 initially_suspended=true;
            alter warehouse identifier(:WAREHOUSE) set comment = :DESCRIPTION;

            for i in 0 to ARRAY_LENGTH do
                CURRENT_ROLE := get(USAGE_ROLES, i);
                grant monitor, operate, usage on warehouse identifier(:WAREHOUSE) to role identifier(:CURRENT_ROLE);
            end for;

            use warehouse identifier(:CALLER_WAREHOUSE);
            use role identifier(:CALLER_ROLE);

            return 'Created warehouse ' || :WAREHOUSE || ' with usage granted to role(s) ' || array_to_string(:USAGE_ROLES, ', ');
        end;
    $$;

    grant ownership on procedure ADMIN.UTILS.CREATE_WAREHOUSE(varchar, varchar, array) to role SYSADMIN;
    grant usage     on procedure ADMIN.UTILS.CREATE_WAREHOUSE(varchar, varchar, array) to role USERADMIN;

create or replace procedure ADMIN.UTILS.CREATE_NORMAL_USER(USERNAME varchar, DEFAULT_ROLE varchar, ADDITIONAL_ROLES array, DESCRIPTION varchar)
    returns varchar
    language sql
    comment = 'Creates a normal user with a default, existing role passed as argument, creates a default warehouse for the user, grants any additional roles to the user and sets a description.'
    execute as caller
    as $$
        declare
            CALLER_ROLE varchar := CURRENT_ROLE();
            ARRAY_LENGTH int := array_size(ADDITIONAL_ROLES) - 1;
            ALL_ROLES array := array_prepend(ADDITIONAL_ROLES, DEFAULT_ROLE);
            CURRENT_ROLE varchar;
            WAREHOUSE_DESCRIPTION varchar := 'For ' || USERNAME;
            RESPONSE varchar;
        begin
            use role USERADMIN;

            create user if not exists identifier(:USERNAME);
            grant role identifier(:DEFAULT_ROLE) to user identifier(:USERNAME);
            alter user identifier(:USERNAME) set login_name = :USERNAME , comment = :DESCRIPTION , default_role = :DEFAULT_ROLE;

            for i in 0 to ARRAY_LENGTH do
                CURRENT_ROLE := get(ADDITIONAL_ROLES, i);
                grant role identifier(:CURRENT_ROLE) to user identifier(:USERNAME);
            end for;

            call ADMIN.UTILS.CREATE_WAREHOUSE(:USERNAME, :WAREHOUSE_DESCRIPTION, :ALL_ROLES);

            alter user identifier(:USERNAME) set default_warehouse = :USERNAME;

            use role identifier(:CALLER_ROLE);

            if (ARRAY_LENGTH = -1) then
                response := 'Created normal user ' || :USERNAME || ', default individual warehouse ' || :USERNAME || ', and set default role to ' || :DEFAULT_ROLE;
            else
                response := 'Created normal user ' || :USERNAME || ', default individual warehouse ' || :USERNAME || ', set default role to ' || :DEFAULT_ROLE || ', and granted additional role(s) ' || array_to_string(:ADDITIONAL_ROLES, ', ');
            end if;

            return response;
        end;
    $$;

    grant usage on procedure ADMIN.UTILS.CREATE_NORMAL_USER(varchar, varchar, array, varchar) to role USERADMIN;


/* As above without the additional_roles argument. */
/* This procedure is typically used for creating human users who can share a role with others in their team (e.g. ANALYTICS_DEVELOPER). */
create or replace procedure ADMIN.UTILS.CREATE_NORMAL_USER(USERNAME varchar, DEFAULT_ROLE varchar, DESCRIPTION varchar)
    returns varchar
    language sql
    comment = 'Creates a normal user with a default, existing role passed as argument, creates a default warehouse for the user and sets a description.'
    execute as caller
    as $$
        begin
            call ADMIN.UTILS.CREATE_NORMAL_USER(:USERNAME, :DEFAULT_ROLE, array_construct(), :DESCRIPTION);

            return 'Created normal user ' || :USERNAME || ', default individual warehouse ' || :USERNAME || ', and set default role to ' || :DEFAULT_ROLE;
        end;
    $$;

    grant usage on procedure ADMIN.UTILS.CREATE_NORMAL_USER(varchar, varchar, varchar) to role USERADMIN;


/* As above but creates a role for the user. */
/* This procedure is typically used for creating a non-human user (e.g. data loader or BI user), which has a unique set of permission requirements and therefore warrants its own role. */
create or replace procedure ADMIN.UTILS.CREATE_NORMAL_USER(USERNAME varchar, DESCRIPTION varchar)
    returns varchar
    language sql
    comment = 'Creates a normal user, default role, default warehouse and sets a description.'
    execute as caller
    as $$
        declare ROLE_DESCRIPTION varchar := 'Functional role for user ' || USERNAME;
        begin
            call ADMIN.UTILS.CREATE_ROLE(:USERNAME, :ROLE_DESCRIPTION);
            call ADMIN.UTILS.CREATE_NORMAL_USER(:USERNAME, :USERNAME, :DESCRIPTION);

        return 'Created normal user ' || :USERNAME || ', default role ' || :USERNAME || ', and default warehouse ' || :USERNAME;
        end;
    $$;

    grant usage on procedure ADMIN.UTILS.CREATE_NORMAL_USER(varchar, varchar) to role USERADMIN;


create or replace procedure ADMIN.UTILS.CREATE_ADMIN_USER(USERNAME varchar, ADMIN_ROLE varchar, DESCRIPTION varchar)
    returns varchar
    language sql
    comment = 'Creates a user granted the specified admin role, and an individual warehouse for the user.'
    execute as caller
    as $$
        declare
            ROLE_UPPERCASE varchar := UPPER(ADMIN_ROLE);
            ADMIN_DESCRIPTION varchar := ROLE_UPPERCASE || ': ' || DESCRIPTION;
            WAREHOUSE_DESCRIPTION varchar := 'For user ' || USERNAME;
            DEFAULT_ROLE varchar;
        begin
            use role ACCOUNTADMIN;
            create user if not exists identifier(:USERNAME);
            alter user identifier(:USERNAME) set login_name = :USERNAME, comment = :ADMIN_DESCRIPTION;
            grant role identifier(:ROLE_UPPERCASE) to user identifier(:USERNAME);

            /* Account admins are set to use the SYSADMIN role by default, so they have to manually switch to the top-level ACCOUNTADMIN role only when necessary. */
            if (ROLE_UPPERCASE = 'ACCOUNTADMIN') then
                DEFAULT_ROLE := 'SYSADMIN';
            else
                DEFAULT_ROLE := ROLE_UPPERCASE;
            end if;

            alter user identifier(:USERNAME) set default_role = :DEFAULT_ROLE;

            /* We're not creating individual roles for admin users, so we grant warehouse usage to all admin roles they might use. */
            call ADMIN.UTILS.CREATE_WAREHOUSE(:USERNAME, :WAREHOUSE_DESCRIPTION, array_construct('SYSADMIN', 'SECURITYADMIN', 'USERADMIN'));
            alter user identifier(:USERNAME) set default_warehouse = :USERNAME;

            return 'Created admin user ' || :USERNAME || ', granted role ' || :ADMIN_ROLE || ', and individual warehouse ' || :USERNAME;
        end;
    $$;

    /* There is intentionally no grant on the CREATE_ADMIN_USER procedure, as only account admins should be allowed to run it. */
