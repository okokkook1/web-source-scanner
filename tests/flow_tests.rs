use web_source_scanner::{flow, model::*};

fn source(name: &str, text: &str) -> SourceFile {
    SourceFile {
        relative: name.into(),
        text: text.into(),
        encoding: "utf-8".into(),
        extension: "cs".into(),
    }
}

fn chain(service_body: &str, repository_body: &str) -> Vec<SourceFile> {
    vec![
        source(
            "Controllers/HomeController.cs",
            r#"using System.Web.Mvc;
public class HomeController : Controller
{
    public ActionResult Index(string name)
    {
        var service = new UserService();
        return View(service.Find(name));
    }
}
"#,
        ),
        source(
            "Services/UserService.cs",
            &format!(
                r#"public class UserService
{{
    public object Find(string key)
    {{
{service_body}
    }}
}}
"#
            ),
        ),
        source(
            "Services/Repository.cs",
            &format!(
                r#"public class Repository
{{
    public object Lookup(string q)
    {{
{repository_body}
    }}
}}
"#
            ),
        ),
    ]
}

#[test]
fn cross_file_parameter_reaches_sql_sink() {
    let files = chain(
        "        var repo = new Repository();\n        return repo.Lookup(key);",
        "        var sql = \"SELECT * FROM Users WHERE Name = N'\" + q + \"'\";\n        var cmd = new SqlCommand(sql, connection);\n        return cmd.ExecuteScalar();",
    );
    let outcome = flow::analyze(&files);
    let hit = outcome
        .findings
        .iter()
        .find(|f| f.rule_id == "FLOW-SQL")
        .unwrap_or_else(|| panic!("missing cross-file finding: {:#?}", outcome.findings));
    assert_eq!(hit.file, "Services/Repository.cs");
    assert_eq!(hit.start_line, 6);
    assert_eq!(hit.confidence, "低");
    assert!(
        hit.evidence.contains("UserService.Find"),
        "{}",
        hit.evidence
    );
    assert!(hit.evidence.contains("Controllers/HomeController.cs"));
    assert_eq!(outcome.methods, 3);
}

#[test]
fn parameterized_query_does_not_report_a_cross_file_sql_flow() {
    let files = chain(
        "        var repo = new Repository();\n        return repo.Lookup(key);",
        "        var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Name = @name\", connection);\n        cmd.Parameters.AddWithValue(\"@name\", q);\n        return cmd.ExecuteScalar();",
    );
    let outcome = flow::analyze(&files);
    assert!(
        !outcome.findings.iter().any(|f| f.rule_id == "FLOW-SQL"),
        "{:#?}",
        outcome.findings
    );
}

#[test]
fn constant_argument_is_not_treated_as_user_input() {
    let mut files = chain(
        "        var repo = new Repository();\n        return repo.Lookup(key);",
        "        var sql = \"SELECT 1 WHERE n=\" + q;\n        var cmd = new SqlCommand(sql, connection);\n        return cmd.ExecuteScalar();",
    );
    files[0].text = files[0].text.replace("Find(name)", "Find(\"fixed\")");
    let outcome = flow::analyze(&files);
    assert!(!outcome.findings.iter().any(|f| f.rule_id == "FLOW-SQL"));
}

#[test]
fn request_input_flowing_into_file_operation_is_reported() {
    let files = vec![
        source(
            "Pages/Report.cs",
            r#"public class Report
{
    public void Run()
    {
        var name = Request.QueryString["file"];
        Storage.Save(name);
    }
}
"#,
        ),
        source(
            "Services/Storage.cs",
            r#"public class Storage
{
    public static void Save(string value)
    {
        File.WriteAllText(value, "template");
    }
}
"#,
        ),
    ];
    let outcome = flow::analyze(&files);
    let hit = outcome
        .findings
        .iter()
        .find(|f| f.rule_id == "FLOW-PATH")
        .unwrap_or_else(|| panic!("missing path finding: {:#?}", outcome.findings));
    assert_eq!(hit.file, "Services/Storage.cs");
    assert_eq!(hit.start_line, 5);
}

#[test]
fn identifiers_inside_sql_strings_do_not_create_taint() {
    // The literal contains the same name as the parameter; it must not be
    // mistaken for the variable itself.
    let files = vec![source(
        "A.cs",
        r#"public class A
{
    public void Run(string q)
    {
        Query("q");
    }
    public void Query(string q)
    {
        var sql = "SELECT q FROM t";
        var cmd = new SqlCommand(sql, connection);
    }
}
"#,
    )];
    let outcome = flow::analyze(&files);
    assert!(!outcome.findings.iter().any(|f| f.rule_id == "FLOW-SQL"));
}

#[test]
fn no_source_means_no_cross_file_finding() {
    let files = vec![source(
        "A.cs",
        r#"public class A
{
    public void Run(string value)
    {
        Query(value);
    }
    public void Query(string q)
    {
        var sql = "SELECT " + q;
        var cmd = new SqlCommand(sql, connection);
    }
}
"#,
    )];
    let outcome = flow::analyze(&files);
    assert!(outcome.findings.is_empty());
}
