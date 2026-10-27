using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
class Test {
 void Bad() {
  var user = Request.QueryString["name"];
  var sql = "SELECT * FROM users WHERE name='" + user + "'";
  // ruleid: ENGINE-SQL-TAINT
  var cmd = new SqlCommand(sql, connection);
  // ruleid: ENGINE-COMMAND-TAINT
  Process.Start(Request["cmd"]);
  // ruleid: ENGINE-PATH-TAINT
  File.ReadAllText(Request.Form["path"]);
  // ruleid: ENGINE-TLS-BYPASS
  ServicePointManager.ServerCertificateValidationCallback = (a,b,c,d) => true;
  // ruleid: ENGINE-WEAK-CRYPTO
  var hash = MD5.Create();
  var bf = new BinaryFormatter();
  // ruleid: ENGINE-DESERIALIZE
  bf.Deserialize(stream);
  // ruleid: ENGINE-RAW-HTML
  Html.Raw(user);
 }
 // ruleid: ENGINE-MVC-VALIDATION
 [ValidateInput(false)]
 public ActionResult Save() { return View(); }
 void Safe() {
  var name = Request.QueryString["name"];
  // ok: ENGINE-SQL-TAINT
  var cmd = new SqlCommand("SELECT * FROM users WHERE name=@name", connection);
  cmd.Parameters.AddWithValue("@name", name);
  // ok: ENGINE-COMMAND-TAINT
  Process.Start("trusted.exe");
  // ok: ENGINE-PATH-TAINT
  File.ReadAllText("fixed.txt");
  // ok: ENGINE-TLS-BYPASS
  ServicePointManager.ServerCertificateValidationCallback = CheckCertificate;
  // ok: ENGINE-WEAK-CRYPTO
  var hash = SHA256.Create();
  // ok: ENGINE-DESERIALIZE
  JsonSerializer.Deserialize<Model>(json);
  // ok: ENGINE-RAW-HTML
  Html.Encode(name);
 }
 // ok: ENGINE-MVC-VALIDATION
 [ValidateInput(true)]
 public ActionResult SafeSave() { return View(); }
}
