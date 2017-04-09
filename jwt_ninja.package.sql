create or replace package jwt_ninja

as

  /** This package implements JWT (Java Web Tokens, https://jwt.io/) in plsql
  * @author Morten Egan
  * @version 0.0.1
  * @project jwt_ninja
  */
  npg_version               varchar2(250) := '0.0.1';

  /* JWT default encryption key */
  g_encryption_key          varchar2(150) := null;

  /* JWT JOSE header defaults */
  g_header_alg              varchar2(150) := 'HS256';
  g_header_typ              varchar2(150) := 'JWT';
  g_header_cty              varchar2(150) := null;

  /* JWT Claims registered claims defaults */
  g_reg_claim_issuer        varchar2(4000) := null;
  g_reg_claim_subject       varchar2(4000) := null;
  g_reg_claim_audience      varchar2(4000) := null;
  g_reg_claim_expiration    number := null;
  g_reg_claim_notbefore     number := null;
  g_reg_claim_issuedat      number := null;
  g_reg_claim_expiration_d  date := null;
  g_reg_claim_notbefore_d   date := null;
  g_reg_claim_issuedat_d    date := null;
  g_reg_claim_jwtid         varchar2(4000) := null;

  /** Generate JWT token
  * @author Morten Egan
  * @return varchar2 The string representation of the JWT token
  */
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
  return varchar2;

  /** Verify and Decode the JWT token.
  * @author Morten Egan
  * @param p_token The token that should be verified and decoded.
  */
  procedure jwt_verify_and_decode (
    p_token                   in          varchar2
    , p_secret                in          varchar2
    , p_do_parse              in          boolean default false
    , p_verified              out         boolean
    , p_reg_claim_issuer      out         varchar2
    , p_reg_claim_subject     out         varchar2
    , p_reg_claim_audience    out         varchar2
    , p_reg_claim_expiration  out         date
    , p_reg_claim_notbefore   out         date
    , p_reg_claim_issuedat    out         date
    , p_reg_claim_jwtid       out         varchar2
  );

end jwt_ninja;
/
