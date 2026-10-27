use web_source_scanner::{model::*, rules::*};
fn check(ext: &str, text: &str, id: &str) -> Vec<Finding> {
    analyze_source(&SourceFile {
        relative: format!("測試/A.{ext}"),
        text: text.into(),
        encoding: "UTF-8".into(),
        extension: ext.into(),
    })
    .into_iter()
    .filter(|f| f.rule_id == id)
    .collect()
}

#[test]
fn hardcoded_secret_detected_and_redacted_without_reporting_placeholders() {
    let f = check(
        "cs",
        r#"class A { string password = "exampleSecret123"; }"#,
        "LOCAL-SECRET",
    );
    assert_eq!(f.len(), 1);
    assert!(!f[0].evidence.contains("exampleSecret123"));
    assert!(check("cs", r#"string password = "${PASSWORD}";"#, "LOCAL-SECRET").is_empty());
    assert!(
        check(
            "cs",
            r#"// string password = "exampleSecret456";"#,
            "LOCAL-SECRET"
        )
        .is_empty()
    );
}

#[test]
fn report_redaction_masks_xml_connectionstrings_bearer_and_private_keys() {
    for (input, secret) in [
        (r#"password="exampleSecret789""#, "exampleSecret789"),
        (
            r#"Password=exampleSecret789;User Id=admin;"#,
            "exampleSecret789",
        ),
        (
            "Bearer exampleTokenABCDEF1234567890",
            "exampleTokenABCDEF1234567890",
        ),
        (
            "-----BEGIN PRIVATE KEY-----\nABC123\n-----END PRIVATE KEY-----",
            "ABC123",
        ),
    ] {
        let safe = redact(input);
        assert!(!safe.contains(secret), "{safe}");
        assert!(safe.contains("遮蔽"));
    }
}

#[test]
fn redact_entire_secrets_with_spaces_and_xml_appsettings_values() {
    for input in [
        r#"string password = "top secret suffix";"#,
        r#"Password=top secret suffix;User Id=admin"#,
        r#"<add value="top secret suffix" key="ApiKey"/>"#,
        r#"{"client_secret":"top secret suffix"}"#,
    ] {
        let safe = redact(input);
        assert!(!safe.contains("suffix"), "secret tail leaked: {safe}");
        assert!(safe.contains("遮蔽"));
    }
    assert_eq!(
        check(
            "config",
            r#"<add value="exampleSecret321" key="ApiKey"/>"#,
            "LOCAL-SECRET"
        )
        .len(),
        1
    );
    assert!(
        check(
            "config",
            r#"<add value="${APIKEY}" key="ApiKey"/>"#,
            "LOCAL-SECRET"
        )
        .is_empty()
    );
    assert_eq!(
        check(
            "config",
            r#"<add connectionString="Server=local;Password=plain password;User Id=a;"/>"#,
            "LOCAL-SECRET"
        )
        .len(),
        1
    );
}

#[test]
fn xml_settings_are_attribute_order_independent_and_ignore_comments() {
    for (id, bad, good) in [
        (
            "CONFIG-DEBUG",
            r#"<compilation targetFramework="4.5" debug="true"/>"#,
            r#"<compilation debug="false"/>"#,
        ),
        (
            "CONFIG-ERRORS",
            r#"<customErrors defaultRedirect="error" mode="Off"/>"#,
            r#"<customErrors mode="On"/>"#,
        ),
        (
            "CONFIG-COOKIE",
            r#"<httpCookies httpOnlyCookies="false" requireSSL="false"/>"#,
            r#"<httpCookies httpOnlyCookies="true" requireSSL="true"/>"#,
        ),
        (
            "CONFIG-VALIDATION",
            r#"<pages validateRequest="false"/>"#,
            r#"<pages validateRequest="true"/>"#,
        ),
    ] {
        assert!(!check("config", bad, id).is_empty(), "{id}");
        assert!(check("config", good, id).is_empty(), "{id}");
        assert!(check("config", &format!("<!--{bad}-->"), id).is_empty());
    }
}

#[test]
fn razor_raw_html_requires_review_but_encoded_output_is_not_reported() {
    let f = check("cshtml", "<p>@Html.Raw(Model.Text)</p>", "RAZOR-RAW");
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].confidence, "低");
    assert!(f[0].review_status.contains("人工"));
    assert!(check("cshtml", "<p>@Html.Encode(Model.Text)</p>", "RAZOR-RAW").is_empty());
    assert!(check("cshtml", "@* @Html.Raw(Model.Text) *@", "RAZOR-RAW").is_empty());
}

#[test]
fn ast_empty_catch_ignores_comment_and_string_braces() {
    assert_eq!(
        check(
            "cs",
            "class A { void F() {try { Go(); } catch (Exception ex) { /* explain } */ }}}",
            "QUALITY-EMPTY-CATCH"
        )
        .len(),
        1
    );
    assert!(
        check(
            "cs",
            "class A { void F() {try { Go(); } catch { Log(\"} {\"); throw; }}}",
            "QUALITY-EMPTY-CATCH"
        )
        .is_empty()
    );
}

#[test]
fn ast_throw_variable_is_distinguished_from_rethrow() {
    assert_eq!(
        check(
            "cs",
            "class A { void F(){try{}catch(Exception ex){throw ex;}}}",
            "QUALITY-THROW"
        )
        .len(),
        1
    );
    assert!(
        check(
            "cs",
            "class A { void F(){try{}catch(Exception ex){throw;}}}",
            "QUALITY-THROW"
        )
        .is_empty()
    );
}

#[test]
fn ast_loop_queries_distinguish_queries_before_loop_and_inside_string() {
    let bad = "class A {void F(){foreach(var x in xs){ DBUtility.GetDBData(sql); }}}";
    assert_eq!(check("cs", bad, "PERF-LOOP-QUERY").len(), 1);
    for good in [
        "class A {void F(){var r=DBUtility.GetDBData(sql); foreach(var x in r){Use(x);}}}",
        "class A {void F(){foreach(var x in xs){ Log(\"DBUtility.GetDBData(sql)\"); }}}",
    ] {
        assert!(check("cs", good, "PERF-LOOP-QUERY").is_empty());
    }
}

#[test]
fn synchronous_wait_and_sleep_are_performance_hints() {
    assert_eq!(
        check(
            "cs",
            "class A {void F(){var x=client.GetAsync(url).Result;}}",
            "PERF-SYNC-WAIT"
        )
        .len(),
        1
    );
    assert!(
        check(
            "cs",
            "class A {async Task F(){var x=await client.GetAsync(url);}}",
            "PERF-SYNC-WAIT"
        )
        .is_empty()
    );
    assert_eq!(
        check(
            "cs",
            "class A {void F(){Thread.Sleep(1000);}}",
            "PERF-SLEEP"
        )
        .len(),
        1
    );
    assert!(
        check(
            "cs",
            "class A {void F(){Log(\"Thread.Sleep(1000)\");}}",
            "PERF-SLEEP"
        )
        .is_empty()
    );
}

#[test]
fn method_length_and_nesting_use_actual_method_nodes() {
    let body = (0..85).map(|_| "Use();").collect::<Vec<_>>().join("\n");
    assert_eq!(
        check(
            "cs",
            &format!("class A {{void F(){{\n{body}\n}}}}"),
            "QUALITY-LONG-METHOD"
        )
        .len(),
        1
    );
    assert!(
        check(
            "cs",
            "class A {void F(){Log(\"{ { { { {\");}}",
            "QUALITY-NESTING"
        )
        .is_empty()
    );
    assert_eq!(
        check(
            "cs",
            "class A {void F(){if(a){if(b){if(c){if(d){if(e){Use();}}}}}}}",
            "QUALITY-NESTING"
        )
        .len(),
        1
    );
}

#[test]
fn stream_creation_without_using_is_a_review_hint() {
    assert_eq!(
        check(
            "cs",
            r#"class A {void F(){var s=new FileStream(path, FileMode.Open);}}"#,
            "QUALITY-RESOURCE"
        )
        .len(),
        1
    );
    assert!(
        check(
            "cs",
            r#"class A {void F(){using(var s=new FileStream(path, FileMode.Open)){Use(s);}}}"#,
            "QUALITY-RESOURCE"
        )
        .is_empty()
    );
}
