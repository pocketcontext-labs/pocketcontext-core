package appserver

import (
	"html/template"
	"net/http"
	"strings"
)

// oauthPageTemplate is the consent page chrome. Product sentences come from
// Text.OAuthConsent and are parsed with it: they are trusted static strings from
// the application. {{.Name}} stays client-supplied and is escaped by html/template.
const oauthPageTemplate = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Title}} · {{.Product}}</title>
<style>body{font:18px system-ui,sans-serif;background:#f5f3ed;color:#233c32;max-width:620px;margin:8vh auto;padding:24px;line-height:1.5;overflow-wrap:anywhere}button,a{font:inherit}button{padding:10px 18px;margin:8px 8px 8px 0;cursor:pointer}h1{line-height:1.15}#message{white-space:pre-wrap}li{margin:20px 0;overflow-wrap:anywhere}small{display:block;overflow-wrap:anywhere}a{color:inherit}</style>
<script src="/oauth/app.js" defer></script></head><body data-connections="{{.Connections}}"><p>{{.Product}}</p><h1>{{.Title}}</h1>
{{if .Connections}}@@CONNECTIONS@@<ul id="connections"></ul><button id="reload">Refresh connections</button>
{{else}}@@REQUEST@@<p>The app name is supplied by its developer. Check that you intended to connect it.</p><small>Registered callback: {{.Redirect}}</small><button id="approve">Allow access</button><button id="deny">Cancel</button>{{end}}
<p id="message" role="status"></p><p>{{if .Hosted}}To sign in, <a href="/" target="_blank" rel="noopener">open the reader</a> and choose Log in with email, then return here.{{else}}If you are not signed in, open your fresh {{.Product}} reader sign-in link in another tab of this browser, then return here. Your setup agent can issue one with <code>open --public</code>. You can also <a href="/" target="_blank" rel="noopener">open the reader</a> and use your password if you set one.{{end}}</p><p><a href="/oauth/connections">Manage connected apps</a></p></body></html>`

func newOAuthTemplate(consent OAuthConsentText) (*template.Template, error) {
	source := strings.Replace(oauthPageTemplate, "@@CONNECTIONS@@", consent.ConnectionsHTML, 1)
	source = strings.Replace(source, "@@REQUEST@@", consent.RequestHTML, 1)
	return template.New("oauth").Parse(source)
}

func (o *mcpOAuth) oauthPage(w http.ResponseWriter, title, name, redirect string, connections bool, hosted ...bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = o.rt.oauthTemplate.Execute(w, struct {
		Title, Name, Redirect, Product string
		Connections                    bool
		Hosted                         bool
	}{title, name, redirect, o.rt.cfg.Identity.DisplayName, connections, len(hosted) > 0 && hosted[0]})
}

func oauthScript(storageKey string) string {
	return `"use strict";
const message=document.getElementById("message");
function token(){try{return JSON.parse(localStorage.getItem(` + jsString(storageKey) + `)||"{}").token||""}catch{return ""}}
async function request(path,body){
 const t=token();if(!t)throw Error("Sign in to the reader in this browser first, then return here.");
 const response=await fetch(path,{method:body===undefined?"GET":"POST",credentials:"omit",headers:{Authorization:"Bearer "+t,Accept:"application/json","Content-Type":"application/json"},body:body===undefined?undefined:JSON.stringify(body),redirect:"error"});
 const result=await response.json();if(!response.ok)throw Error(result.error_description||"Request failed. Please sign in again.");return result;
}
async function consent(approve){
 const buttons=document.querySelectorAll("button");buttons.forEach(b=>b.disabled=true);message.textContent="";
 try{const result=await request("/oauth/authorize"+location.search,{approve});location.assign(result.redirect)}catch(e){message.textContent=e.message;buttons.forEach(b=>b.disabled=false)}
}
async function connections(){
 const list=document.getElementById("connections");list.replaceChildren();message.textContent="";
 try{const result=await request("/oauth/connections");for(const item of result.connections){const li=document.createElement("li"),label=document.createElement("span"),button=document.createElement("button");label.textContent=item.name+" — connected "+new Date(item.created*1000).toLocaleDateString();button.textContent="Revoke access";button.onclick=async()=>{button.disabled=true;try{await request("/oauth/connections",{id:item.id});await connections();message.textContent="Access revoked."}catch(e){message.textContent=e.message;button.disabled=false}};li.append(label,document.createElement("br"),button);list.append(li)}if(!result.connections.length)message.textContent="No connected apps."}catch(e){message.textContent=e.message}
}
if(document.body.dataset.connections==="true"){document.getElementById("reload").onclick=connections;connections()}else{document.getElementById("approve").onclick=()=>consent(true);document.getElementById("deny").onclick=()=>consent(false)}
`
}
