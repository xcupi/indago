package web_test

import "testing"

func TestUILoginCarriesProjectScope(t *testing.T) {
	u := newUIHarness(t)
	got := u.eval(`(async()=>{
  let sent=null;
  mutate=async(method,path,body)=>{sent=body;return {ok:false,error:"test rejection"};};
  openLoginModal(()=>{}, "selected-project");
  document.getElementById("l_url").value="http://127.0.0.1/login";
  Array.from(document.querySelectorAll("button")).find(b=>b.textContent==="Open browser & wait").click();
  await new Promise(r=>setTimeout(r,50));
  return sent && sent.project_id;
 })()`)
	if got != "selected-project" {
		t.Fatalf("login request lost project context: %v", got)
	}
}
