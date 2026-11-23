package browser

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	pw "github.com/mxschmitt/playwright-go"
)

// ErrPDFDriverUnavailable lets the web renderer use Chrome's standalone
// print command when the optional Playwright driver is unavailable.
var ErrPDFDriverUnavailable = errors.New("PDF Playwright driver unavailable")

type pdfDriver struct{ *pw.Playwright }

func (d *pdfDriver) Close() error { return d.Stop() }

// PrintPDF uses a separate, offline Chromium instance so report generation
// can run independently of any scan browsers.
func PrintPDF(ctx context.Context, executable string, disableSandbox bool, html []byte) ([]byte, error) {
	driver, err := callCtxCreate(ctx, func() (*pdfDriver, error) {
		p, err := pw.Run()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrPDFDriverUnavailable, err)
		}
		return &pdfDriver{p}, nil
	})
	if err != nil {
		return nil, err
	}
	stopOnCancel := context.AfterFunc(ctx, func() { _ = driver.Close() })
	defer func() {
		if stopOnCancel() {
			_ = driver.Close()
		}
	}()

	return callCtx(ctx, func() ([]byte, error) {
		b, err := driver.Chromium.Launch(pw.BrowserTypeLaunchOptions{
			ExecutablePath:  pw.String(executable),
			Headless:        pw.Bool(true),
			ChromiumSandbox: pw.Bool(!disableSandbox),
		})
		if err != nil {
			return nil, fmt.Errorf("launch PDF Chromium: %w", err)
		}
		defer b.Close()
		page, err := b.NewPage(pw.BrowserNewPageOptions{
			Offline:           pw.Bool(true),
			JavaScriptEnabled: pw.Bool(false),
			ServiceWorkers:    pw.ServiceWorkerPolicyBlock,
		})
		if err != nil {
			return nil, fmt.Errorf("open PDF page: %w", err)
		}
		if err := page.SetContent(string(html)); err != nil {
			return nil, fmt.Errorf("load PDF document: %w", err)
		}
		pdf, err := page.PDF(pw.PagePdfOptions{
			PreferCSSPageSize: pw.Bool(true),
			PrintBackground:   pw.Bool(true),
		})
		if err != nil {
			return nil, fmt.Errorf("print PDF document: %w", err)
		}
		if !bytes.HasPrefix(pdf, []byte("%PDF-")) {
			return nil, errors.New("Chromium did not return a PDF")
		}
		return pdf, nil
	})
}
