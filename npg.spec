[npgstart]
[options]
ninjaversion: 1.0.0
ninjaformat: meta+data
[metadata]
name: jwt_ninja
version: 0.0.1
author: Ninja
description: Generate JWTs (javascript web tokens) in PLSQL.
builddate: 16-08-2016
key: c382dd7ea2016568c2b3e5f78048853c
[require]
execute: dbms_crypto
ordbms: ver_le_11_2
privilege: create procedure
[files]
install.order: order file
jwt_ninja.package.sql: package
jwt_ninja.package body.sql: package body
[npgend]
