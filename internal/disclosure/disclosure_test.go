package disclosure_test

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/disclosure"
)

func TestClassifyDebugPage(t *testing.T) {
	phpinfo := []byte(`<html><head><title>phpinfo()</title></head><body>
<h1 class="p">PHP Version 7.4.3</h1>
<table><tr><td>Configuration File (php.ini) Path</td><td>/etc/php/7.4</td></tr>
<tr><td>SECRET_KEY</td><td>s3cr3t-env-value</td></tr></table>
<h1>PHP Credits</h1></body></html>`)

	v, ok := disclosure.Classify("https://h/cgi-bin/phpinfo.php", 200, "text/html", phpinfo)
	if !ok || v.Kind != disclosure.KindDebugPage {
		t.Fatalf("Classify(phpinfo) = %+v ok=%v, want debug_page", v, ok)
	}
	if v.Detail != "secret_key" {
		t.Fatalf("detail = %q, want the sensitive key the page leaked", v.Detail)
	}

	// A normal page mentioning "PHP Version" in prose is not a debug dump.
	if _, ok := disclosure.Classify("https://h/about", 200, "text/html",
		[]byte(`<p>We upgraded to PHP Version 8 and wrote about PHP Credits.</p>`)); ok {
		t.Fatal("a page that only mentions phpinfo words must not be classified")
	}

	// A debug page that answers 404 is not reachable evidence.
	if _, ok := disclosure.Classify("https://h/cgi-bin/phpinfo.php", 404, "text/html", phpinfo); ok {
		t.Fatal("a 404 must never confirm a debug page")
	}
}

func TestClassifyBackupSource(t *testing.T) {
	java := []byte(`package com.example;

import java.sql.*;

public class ProductTemplate {
    private static final String DB_PASSWORD = "s3cr3t";
}
`)

	v, ok := disclosure.Classify("https://h/backup/ProductTemplate.java.bak", 200, "text/plain", java)
	if !ok || v.Kind != disclosure.KindBackupSource {
		t.Fatalf("Classify(java .bak) = %+v ok=%v, want backup_source", v, ok)
	}
	if v.Detail != "db_password" {
		t.Fatalf("detail = %q, want the credential the source carries", v.Detail)
	}

	// A backup URL that answers a rendered page is not source disclosure.
	if _, ok := disclosure.Classify("https://h/backup/x.php.bak", 200, "text/html", []byte(`<html><body>Not found</body></html>`)); ok {
		t.Fatal("an HTML response under a backup name must not be classified")
	}
	// A backup URL with no code markers is not source disclosure either.
	if _, ok := disclosure.Classify("https://h/backup/data.csv.bak", 200, "text/plain", []byte("a,b,c\n1,2,3\n")); ok {
		t.Fatal("a non-source artefact must not be classified")
	}
	// A source file served under its normal name is not a BACKUP artefact.
	if _, ok := disclosure.Classify("https://h/ProductTemplate.java", 200, "text/plain", java); ok {
		t.Fatal("a normal source path is not the backup-file case")
	}
}

func TestLooksInteresting(t *testing.T) {
	for _, u := range []string{"https://h/cgi-bin/phpinfo.php", "https://h/actuator/env", "https://h/backup/a.php.bak", "https://h/x.php~"} {
		if !disclosure.LooksInteresting(u) {
			t.Fatalf("LooksInteresting(%q) = false, want true", u)
		}
	}
	for _, u := range []string{"https://h/product?productId=1", "https://h/login"} {
		if disclosure.LooksInteresting(u) {
			t.Fatalf("LooksInteresting(%q) = true, want false", u)
		}
	}
	if !strings.Contains(string(disclosure.KindDebugPage), "debug") {
		t.Fatal("kind label drifted")
	}
}
