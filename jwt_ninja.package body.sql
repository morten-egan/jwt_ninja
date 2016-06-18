create or replace package body jwt_ninja

as

  gp_secret           varchar2(4000) := 'secret';
  gp_header_enc       varchar2(4000) := null;
  gp_payload_enc      varchar2(4000) := null;
  gp_signature_enc    varchar2(4000) := null;

  function base64this (
    p_string                  in          varchar2
  )
  return varchar2

  as

  begin

    return replace(utl_raw.cast_to_varchar2(utl_encode.base64_encode(utl_raw.cast_to_raw(p_string))),'=');

  end base64this;

  function getepoch (
    p_attime                  in          date default sysdate
  )
  return number

  as

  begin

    return (p_attime- to_date('1-1-1970 00:00:00','MM-DD-YYYY HH24:Mi:SS'))*24*60*60*1000;

  end getepoch;

  function encryptthis (
    p_string                  in          varchar2
    , p_key                   in          varchar2
  )
  return varchar2

  as

    l_set_key                 varchar2(150);

  begin

    if p_key is null then
      l_set_key := gp_secret;
    else
      l_set_key := p_key;
    end if;

    if g_header_alg = 'HS256' then
      return base64this(utl_raw.cast_to_varchar2(dbms_crypto.mac(utl_raw.cast_to_raw(p_string), dbms_crypto.HMAC_SH256, utl_raw.cast_to_raw(gp_secret))));
    elsif g_header_alg = 'HS384' then
      return base64this(utl_raw.cast_to_varchar2(dbms_crypto.mac(utl_raw.cast_to_raw(p_string), dbms_crypto.HMAC_SH384, utl_raw.cast_to_raw(gp_secret))));
    elsif g_header_alg = 'HS512' then
      return base64this(utl_raw.cast_to_varchar2(dbms_crypto.mac(utl_raw.cast_to_raw(p_string), dbms_crypto.HMAC_SH512, utl_raw.cast_to_raw(gp_secret))));
    else
      g_header_alg := 'HS256';
      return base64this(utl_raw.cast_to_varchar2(dbms_crypto.mac(utl_raw.cast_to_raw(p_string), dbms_crypto.HMAC_SH256, utl_raw.cast_to_raw(gp_secret))));
    end if;

  end encryptthis;

  function jwt_generate_int (
    p_header_alg              in          varchar2 default g_header_alg
    , p_header_typ            in          varchar2 default g_header_typ
    , p_header_cty            in          varchar2 default g_header_cty
    , p_reg_claim_issuer      in          varchar2 default g_reg_claim_issuer
    , p_reg_claim_subject     in          varchar2 default g_reg_claim_subject
    , p_reg_claim_audience    in          varchar2 default g_reg_claim_audience
    , p_reg_claim_expiration  in          number default g_reg_claim_expiration
    , p_reg_claim_notbefore   in          number default g_reg_claim_notbefore
    , p_reg_claim_issuedat    in          number default g_reg_claim_issuedat
    , p_reg_claim_jwtid       in          varchar2 default g_reg_claim_jwtid
    , p_signature_key         in          varchar2 default g_encryption_key
  )
  return varchar2

  as

    l_header_data           varchar2(32000);
    l_payload_data          varchar2(32000);
    l_signature_data        varchar2(32000);
    l_ret_var               varchar2(32000);

  begin

    dbms_application_info.set_action('jwt_generate_int');

    -- Generate header data
    l_header_data := '{ "alg": "'|| p_header_alg ||'", "typ": "'|| p_header_typ ||'"';
    if p_header_cty is not null then
      l_header_data := l_header_data || ', "cty": "'|| p_header_cty ||'"';
    end if;
    l_header_data := l_header_data || ' }';

    -- Generate payload data
    l_payload_data := '{';
    if p_reg_claim_issuedat is not null then
      l_payload_data := l_payload_data || ' "iat": ' || to_char(p_reg_claim_issuedat);
    else
      l_payload_data := l_payload_data || ' "iat": ' || to_char(getepoch);
    end if;
    if p_reg_claim_issuer is not null then
      l_payload_data := l_payload_data || ', "iss": "'|| p_reg_claim_issuer ||'"';
    end if;
    if p_reg_claim_subject is not null then
      l_payload_data := l_payload_data || ', "sub": "'|| p_reg_claim_subject ||'"';
    end if;
    if p_reg_claim_audience is not null then
      l_payload_data := l_payload_data || ', "aud": "'|| p_reg_claim_audience ||'"';
    end if;
    if p_reg_claim_expiration is not null then
      l_payload_data := l_payload_data || ', "exp": '|| p_reg_claim_expiration;
    end if;
    if p_reg_claim_notbefore is not null then
      l_payload_data := l_payload_data || ', "nbf": '|| p_reg_claim_notbefore;
    end if;
    if p_reg_claim_jwtid is not null then
      l_payload_data := l_payload_data || ', "jti": "'|| p_reg_claim_jwtid ||'"';
    end if;
    l_payload_data := l_payload_data || '}';

    -- Encode parts
    gp_header_enc := base64this(l_header_data);
    gp_payload_enc := base64this(l_payload_data);

    -- Generate signature data
    l_signature_data := gp_header_enc || '.' || gp_payload_enc;
    gp_signature_enc := encryptthis(l_signature_data, p_signature_key);

    l_ret_var := gp_header_enc || '.' || gp_payload_enc || '.' || gp_signature_enc;

    dbms_application_info.set_action(null);

    return l_ret_var;

    exception
      when others then
        dbms_application_info.set_action(null);
        raise;

  end jwt_generate_int;

  function jwt_generate (
    p_header_alg              in          varchar2 default g_header_alg
    , p_header_typ            in          varchar2 default g_header_typ
    , p_header_cty            in          varchar2 default g_header_cty
    , p_reg_claim_issuer      in          varchar2 default g_reg_claim_issuer
    , p_reg_claim_subject     in          varchar2 default g_reg_claim_subject
    , p_reg_claim_audience    in          varchar2 default g_reg_claim_audience
    , p_reg_claim_expiration  in          date default g_reg_claim_expiration_d
    , p_reg_claim_notbefore   in          date default g_reg_claim_notbefore_d
    , p_reg_claim_issuedat    in          date default g_reg_claim_issuedat_d
    , p_reg_claim_jwtid       in          varchar2 default g_reg_claim_jwtid
    , p_signature_key         in          varchar2 default g_encryption_key
  )
  return varchar2

  as

    l_ret_var               varchar2(32000);

    l_exp                   number := null;
    l_nbf                   number := null;
    l_iat                   number := null;

  begin

    dbms_application_info.set_action('jwt_generate');

    if p_reg_claim_expiration is not null then
      l_exp := getepoch(p_reg_claim_expiration);
    end if;

    if p_reg_claim_notbefore is not null then
      l_nbf := getepoch(p_reg_claim_notbefore);
    end if;

    if p_reg_claim_issuedat is not null then
      l_iat := getepoch(p_reg_claim_issuedat);
    end if;

    l_ret_var := jwt_generate_int(
      p_header_alg
      , p_header_typ
      , p_header_cty
      , p_reg_claim_issuer
      , p_reg_claim_subject
      , p_reg_claim_audience
      , l_exp
      , l_nbf
      , l_iat
      , p_reg_claim_jwtid
      , p_signature_key
    );

    dbms_application_info.set_action(null);

    return l_ret_var;

    exception
      when others then
        dbms_application_info.set_action(null);
        raise;

  end jwt_generate;

begin

  dbms_application_info.set_client_info('jwt_ninja');
  dbms_session.set_identifier('jwt_ninja');

end jwt_ninja;
/
