package templates

import (
	"fmt"
	"html/template"
	"io"
	"path/filepath"
	"strings"
)

// Renderer 模板渲染器
type Renderer struct {
	templates map[string]*template.Template
	basePath  string
}

// NewRenderer 创建新的模板渲染器
func NewRenderer(basePath string) *Renderer {
	return &Renderer{
		templates: make(map[string]*template.Template),
		basePath:  basePath,
	}
}

// LoadTemplates 加载所有模板
func (r *Renderer) LoadTemplates() error {
	// 加载基础布局模板
	baseTemplate := filepath.Join(r.basePath, "layout", "base.html")
	headerTemplate := filepath.Join(r.basePath, "partials", "header.html")

	// 定义模板映射
	templateMap := map[string][]string{
		"login": {
			baseTemplate,
			filepath.Join(r.basePath, "auth", "login.html"),
		},
		"dashboard": {
			baseTemplate,
			headerTemplate,
			filepath.Join(r.basePath, "dashboard", "index.html"),
		},
		"interfaces": {
			baseTemplate,
			headerTemplate,
			filepath.Join(r.basePath, "interfaces", "index.html"),
		},
		"routes": {
			baseTemplate,
			headerTemplate,
			filepath.Join(r.basePath, "routes", "index.html"),
		},
		"arp": {
			baseTemplate,
			headerTemplate,
			filepath.Join(r.basePath, "arp", "index.html"),
		},
		"firewall": {
			baseTemplate,
			headerTemplate,
			filepath.Join(r.basePath, "firewall", "index.html"),
		},
		"dhcp": {
			baseTemplate,
			headerTemplate,
			filepath.Join(r.basePath, "dhcp", "index.html"),
		},
		"vpn": {
			baseTemplate,
			headerTemplate,
			filepath.Join(r.basePath, "vpn", "index.html"),
		},
		"qos": {
			baseTemplate,
			headerTemplate,
			filepath.Join(r.basePath, "qos", "index.html"),
		},
	}

	// 加载每个模板
	for name, files := range templateMap {
		tmpl, err := template.ParseFiles(files...)
		if err != nil {
			return fmt.Errorf("failed to parse template %s: %w", name, err)
		}
		r.templates[name] = tmpl
	}

	return nil
}

// Render 渲染模板
func (r *Renderer) Render(w io.Writer, name string, data interface{}) error {
	tmpl, exists := r.templates[name]
	if !exists {
		return fmt.Errorf("template %s not found", name)
	}

	return tmpl.ExecuteTemplate(w, "base.html", data)
}

// RenderString 渲染模板为字符串
func (r *Renderer) RenderString(name string, data interface{}) (string, error) {
	tmpl, exists := r.templates[name]
	if !exists {
		return "", fmt.Errorf("template %s not found", name)
	}

	var buf strings.Builder
	err := tmpl.ExecuteTemplate(&buf, "base.html", data)
	return buf.String(), err
}

// TemplateData 模板数据结构
type TemplateData struct {
	Title string
	Data  interface{}
	User  interface{}
}
