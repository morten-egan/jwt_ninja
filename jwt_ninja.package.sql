create or replace package jwt_ninja

as

  /** This package implements JWT (Java Web Tokens, https://jwt.io/) in plsql
  * @author Morten Egan
  * @version 0.0.1
  * @project jwt_ninja
  */
  npg_version               varchar2(250) := '0.0.1';

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
    , p_reg_claim_expiration  in          number default g_reg_claim_expiration
    , p_reg_claim_notbefore   in          number default g_reg_claim_notbefore
    , p_reg_claim_issuedat    in          number default g_reg_claim_issuedat
    , p_reg_claim_jwtid       in          varchar2 default g_reg_claim_jwtid
  )
  return varchar2;

end jwt_ninja;
/
