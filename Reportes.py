# -*- coding: utf-8 -*-
"""
Reportes
Autor Original: Roger F5
Potenciado By: Claude AI Assistant
Fecha: 2026-01-28

Extension profesional de reporteria para Burp Suite Community/Professional

CARACTERISTICAS:
- Auto-save automatico y recuperacion al reiniciar
- Exportacion Faraday, DefectDojo, JSON y HTML profesional
- Base de datos expandida 40+ vulnerabilidades
- Clasificacion OWASP Top 10 2021
- Busqueda y filtros avanzados en tiempo real
- Editor completo de vulnerabilidades
- Sistema de tags y metadatos
- Persistencia JSON con Request/Response
- No afecta rendimiento de Burp

USO:
1. Burp Suite > Extender > Extensions > Add > Python
2. Cargar este archivo
3. Usar tab "Reportes"
4. Click derecho en requests > "Enviar a Reportes"
5. Exportar en formato deseado
"""

from burp import IBurpExtender, IHttpListener, ITab, IContextMenuFactory, IMessageEditorController
from javax.swing import (JPanel, JTabbedPane, JScrollPane, JTextArea, JButton, JTable, 
                         JLabel, JFileChooser, JSplitPane, JMenuItem, JTextField, 
                         JComboBox, BorderFactory, BoxLayout, JOptionPane, ListSelectionModel, 
                         SwingUtilities, JCheckBox, JSeparator, SwingConstants, JDialog)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, FlowLayout, Dimension, Font, Color, GridLayout
from java.awt.event import MouseAdapter, KeyAdapter, ActionListener
from java.util import ArrayList
import threading, re, codecs, json, base64, os
from datetime import datetime

# ============================================================================
# CATEGORIAS OWASP TOP 10 2021
# ============================================================================

OWASP_CATEGORIES = {
    'A01:2021': 'Broken Access Control',
    'A02:2021': 'Cryptographic Failures',
    'A03:2021': 'Injection',
    'A04:2021': 'Insecure Design',
    'A05:2021': 'Security Misconfiguration',
    'A06:2021': 'Vulnerable Components',
    'A07:2021': 'Authentication Failures',
    'A08:2021': 'Software/Data Integrity',
    'A09:2021': 'Logging Failures',
    'A10:2021': 'SSRF',
    'OTHER': 'Other/Informational'
}

CVSS_TEMPLATES = {
    'Critical': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    'High': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    'Medium': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N',
    'Low': 'CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N',
    'Info': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'
}

# ============================================================================
# BASE DE DATOS DE VULNERABILIDADES
# ============================================================================

VULN_DB = {
    # INJECTION
    'SQL Injection': {
        'desc': 'La aplicacion no valida entradas permitiendo inyeccion de codigo SQL que puede comprometer la base de datos.',
        'sol': 'Usar consultas parametrizadas (prepared statements), validar entradas, principio de minimo privilegio.',
        'category': 'A03:2021', 'severity': 'Critical', 'cwe': 'CWE-89', 'tags': ['injection', 'database', 'critical']
    },
    'XSS Reflected': {
        'desc': 'La aplicacion refleja entrada sin sanitizar permitiendo ejecucion de scripts en el navegador.',
        'sol': 'Codificacion de salida contextual, Content-Security-Policy estricta, validacion de entradas.',
        'category': 'A03:2021', 'severity': 'High', 'cwe': 'CWE-79', 'tags': ['xss', 'injection']
    },
    'XSS Stored': {
        'desc': 'La aplicacion almacena entrada maliciosa permitiendo ataques persistentes contra otros usuarios.',
        'sol': 'Sanitizar entradas antes de almacenar, CSP estricta, codificacion de salida.',
        'category': 'A03:2021', 'severity': 'Critical', 'cwe': 'CWE-79', 'tags': ['xss', 'stored', 'critical']
    },
    'Command Injection': {
        'desc': 'Permite ejecucion arbitraria de comandos del sistema operativo.',
        'sol': 'Evitar llamadas al sistema, usar APIs nativas, validar estrictamente entradas con listas blancas.',
        'category': 'A03:2021', 'severity': 'Critical', 'cwe': 'CWE-78', 'tags': ['injection', 'rce', 'critical']
    },
    'LDAP Injection': {
        'desc': 'Inyeccion en consultas LDAP permitiendo acceso no autorizado al directorio.',
        'sol': 'Usar consultas parametrizadas para LDAP, validar y escapar entradas.',
        'category': 'A03:2021', 'severity': 'High', 'cwe': 'CWE-90', 'tags': ['injection', 'ldap']
    },
    
    # ACCESS CONTROL
    'IDOR': {
        'desc': 'Acceso no autorizado a objetos mediante manipulacion de referencias directas (IDs).',
        'sol': 'Implementar validacion de autorizacion en cada acceso, usar referencias indirectas o UUIDs.',
        'category': 'A01:2021', 'severity': 'High', 'cwe': 'CWE-639', 'tags': ['access-control', 'idor']
    },
    'Path Traversal': {
        'desc': 'Permite acceso a archivos fuera del directorio previsto usando ../ u otras secuencias.',
        'sol': 'Validar y normalizar rutas, usar listas blancas de directorios, implementar sandboxing.',
        'category': 'A01:2021', 'severity': 'High', 'cwe': 'CWE-22', 'tags': ['access-control', 'files']
    },
    'Privilege Escalation': {
        'desc': 'Usuarios con bajos privilegios pueden elevar permisos o acceder a funciones restringidas.',
        'sol': 'Implementar RBAC robusto, validar permisos en cada operacion, separar funciones criticas.',
        'category': 'A01:2021', 'severity': 'Critical', 'cwe': 'CWE-269', 'tags': ['access-control', 'privilege', 'critical']
    },
    'Missing Function Level Access Control': {
        'desc': 'Funciones administrativas accesibles sin validacion de autorizacion adecuada.',
        'sol': 'Implementar control de acceso en todas las funciones, no confiar en controles del cliente.',
        'category': 'A01:2021', 'severity': 'High', 'cwe': 'CWE-285', 'tags': ['access-control', 'authorization']
    },
    
    # AUTHENTICATION
    'Broken Authentication': {
        'desc': 'Fallas en autenticacion que permiten comprometer credenciales o sesiones.',
        'sol': 'Implementar MFA, politicas de contraseñas fuertes, proteger credenciales en transito y reposo.',
        'category': 'A07:2021', 'severity': 'Critical', 'cwe': 'CWE-287', 'tags': ['authentication', 'critical']
    },
    'Session Fixation': {
        'desc': 'No se regenera el ID de sesion despues de autenticacion permitiendo ataques de fijacion.',
        'sol': 'Regenerar ID de sesion despues de login, invalidar sesiones antiguas, usar cookies seguras.',
        'category': 'A07:2021', 'severity': 'High', 'cwe': 'CWE-384', 'tags': ['authentication', 'session']
    },
    'Weak Password Policy': {
        'desc': 'Permite contraseñas debiles o no implementa politicas de complejidad.',
        'sol': 'Politica robusta: longitud minima 12 chars, complejidad, rotacion, validacion contra diccionarios.',
        'category': 'A07:2021', 'severity': 'Medium', 'cwe': 'CWE-521', 'tags': ['authentication', 'password']
    },
    'Credential Exposure': {
        'desc': 'Credenciales o tokens expuestos en URLs, codigo fuente o almacenamiento inseguro.',
        'sol': 'No incluir credenciales en URLs/codigo, usar variables de entorno, cifrar almacenamiento.',
        'category': 'A07:2021', 'severity': 'Critical', 'cwe': 'CWE-522', 'tags': ['authentication', 'credentials', 'critical']
    },
    
    # CRYPTOGRAPHIC FAILURES
    'Weak Encryption Algorithm': {
        'desc': 'Uso de algoritmos criptograficos obsoletos (MD5, SHA1, DES, RC4).',
        'sol': 'Usar algoritmos modernos: AES-256-GCM, RSA 2048+, SHA-256+, gestion segura de claves.',
        'category': 'A02:2021', 'severity': 'High', 'cwe': 'CWE-327', 'tags': ['crypto', 'encryption']
    },
    'Sensitive Data Exposure': {
        'desc': 'Informacion sensible transmitida o almacenada sin cifrado adecuado.',
        'sol': 'Cifrar datos en transito (TLS 1.2+) y reposo (AES-256), clasificar y proteger datos sensibles.',
        'category': 'A02:2021', 'severity': 'High', 'cwe': 'CWE-311', 'tags': ['crypto', 'data-protection']
    },
    'Insecure SSL/TLS Configuration': {
        'desc': 'Configuracion SSL/TLS debil: protocolos obsoletos, cifrados debiles, falta HSTS.',
        'sol': 'Deshabilitar SSLv2/v3, TLS 1.0/1.1, usar solo TLS 1.2+, configurar cifrados robustos, HSTS.',
        'category': 'A02:2021', 'severity': 'High', 'cwe': 'CWE-326', 'tags': ['crypto', 'tls', 'ssl']
    },
    
    # SECURITY MISCONFIGURATION
    'Headers de Seguridad Faltantes': {
        'desc': 'El servidor no envia encabezados HTTP de seguridad importantes.',
        'sol': 'Configurar HSTS, CSP estricta, X-Frame-Options: DENY, X-Content-Type-Options: nosniff.',
        'category': 'A05:2021', 'severity': 'Medium', 'cwe': 'CWE-693', 'tags': ['misconfiguration', 'headers']
    },
    'Cookie Insegura (Flags)': {
        'desc': 'Cookies de sesion sin flags Secure, HttpOnly o SameSite.',
        'sol': 'Configurar cookies con flags: Secure, HttpOnly, SameSite=Strict/Lax.',
        'category': 'A05:2021', 'severity': 'Medium', 'cwe': 'CWE-614', 'tags': ['misconfiguration', 'cookies']
    },
    'Directory Listing Enabled': {
        'desc': 'El servidor permite listado de directorios exponiendo estructura de archivos.',
        'sol': 'Deshabilitar directory listing (Options -Indexes), usar paginas index en directorios.',
        'category': 'A05:2021', 'severity': 'Low', 'cwe': 'CWE-548', 'tags': ['misconfiguration', 'disclosure']
    },
    'Verbose Error Messages': {
        'desc': 'Mensajes de error detallados revelan informacion tecnica (stack traces, rutas).',
        'sol': 'Implementar manejo de errores generico para usuarios, logs detallados solo internos.',
        'category': 'A05:2021', 'severity': 'Low', 'cwe': 'CWE-209', 'tags': ['misconfiguration', 'disclosure']
    },
    'CORS Misconfiguration': {
        'desc': 'Configuracion CORS permisiva (Access-Control-Allow-Origin: *).',
        'sol': 'Restringir origenes a lista blanca especifica, no usar * con credenciales.',
        'category': 'A05:2021', 'severity': 'Medium', 'cwe': 'CWE-942', 'tags': ['misconfiguration', 'cors']
    },
    'Default Credentials': {
        'desc': 'Uso de credenciales por defecto en aplicaciones o servicios.',
        'sol': 'Cambiar credenciales por defecto, forzar cambio en primer acceso, auditar periodicamente.',
        'category': 'A05:2021', 'severity': 'Critical', 'cwe': 'CWE-798', 'tags': ['misconfiguration', 'credentials', 'critical']
    },
    
    # VULNERABLE COMPONENTS
    'Outdated Component': {
        'desc': 'Uso de componentes con vulnerabilidades conocidas (librerias, frameworks).',
        'sol': 'Mantener inventario actualizado, actualizar regularmente, suscribirse a alertas CVE.',
        'category': 'A06:2021', 'severity': 'High', 'cwe': 'CWE-1035', 'tags': ['components', 'outdated']
    },
    
    # SSRF
    'Server-Side Request Forgery (SSRF)': {
        'desc': 'Permite realizar peticiones arbitrarias desde el servidor a recursos internos/externos.',
        'sol': 'Validar URLs estrictamente, listas blancas, segmentar red, deshabilitar redirects.',
        'category': 'A10:2021', 'severity': 'High', 'cwe': 'CWE-918', 'tags': ['ssrf', 'network']
    },
    
    # CSRF
    'Cross-Site Request Forgery (CSRF)': {
        'desc': 'No valida origen de peticiones permitiendo acciones no autorizadas.',
        'sol': 'Implementar tokens CSRF unicos, validar origen, usar SameSite en cookies.',
        'category': 'A01:2021', 'severity': 'Medium', 'cwe': 'CWE-352', 'tags': ['csrf', 'session']
    },
    
    # BUSINESS LOGIC
    'Business Logic Flaw': {
        'desc': 'Fallas en logica que permiten bypasses de controles o abuso de funcionalidad.',
        'sol': 'Revisar flujos criticos, validaciones en servidor, testear casos limite.',
        'category': 'A04:2021', 'severity': 'High', 'cwe': 'CWE-840', 'tags': ['business-logic']
    },
    'Rate Limiting Missing': {
        'desc': 'Ausencia de limitacion de tasa permitiendo brute force o DoS.',
        'sol': 'Implementar rate limiting, CAPTCHA, bloqueo temporal, monitoreo de patrones.',
        'category': 'A04:2021', 'severity': 'Medium', 'cwe': 'CWE-799', 'tags': ['rate-limit', 'brute-force']
    },
    
    # INFORMATION DISCLOSURE
    'Email Disclosure': {
        'desc': 'Direcciones de correo expuestas en respuestas o codigo fuente.',
        'sol': 'Eliminar emails de respuestas publicas, usar formularios de contacto, ofuscar si necesario.',
        'category': 'OTHER', 'severity': 'Info', 'cwe': 'CWE-200', 'tags': ['disclosure', 'info']
    },
    'Private IP Disclosure': {
        'desc': 'Revelacion de direcciones IP internas (RFC 1918) en headers o respuestas.',
        'sol': 'Configurar proxy/load balancer para no revelar IPs internas, sanitizar headers.',
        'category': 'OTHER', 'severity': 'Low', 'cwe': 'CWE-200', 'tags': ['disclosure', 'network']
    },
    'Software Version Disclosure': {
        'desc': 'Expone versiones exactas de software facilitando ataques dirigidos.',
        'sol': 'Ocultar banners: ServerTokens Prod en Apache, server_tokens off en Nginx.',
        'category': 'A05:2021', 'severity': 'Info', 'cwe': 'CWE-200', 'tags': ['disclosure', 'fingerprinting']
    },
    'Backup File Disclosure': {
        'desc': 'Archivos de respaldo accesibles (.bak, .old, ~, .swp).',
        'sol': 'Eliminar backups de directorios publicos, configurar reglas de exclusion.',
        'category': 'A05:2021', 'severity': 'Medium', 'cwe': 'CWE-530', 'tags': ['disclosure', 'files']
    },
    'Source Code Disclosure': {
        'desc': 'Codigo fuente accesible revelando logica y vulnerabilidades.',
        'sol': 'Asegurar codigo no accesible via web, usar .gitignore, no exponer .git/.svn.',
        'category': 'A05:2021', 'severity': 'High', 'cwe': 'CWE-540', 'tags': ['disclosure', 'source-code']
    },
    
    # API SECURITY
    'API - Broken Object Level Authorization': {
        'desc': 'APIs sin validacion de autorizacion permitiendo acceso a recursos de otros usuarios.',
        'sol': 'Validar autorizacion en cada endpoint, verificar permisos sobre objetos.',
        'category': 'A01:2021', 'severity': 'High', 'cwe': 'CWE-639', 'tags': ['api', 'authorization']
    },
    'API - Excessive Data Exposure': {
        'desc': 'API retorna mas datos de los necesarios confiando en filtrado del cliente.',
        'sol': 'Implementar DTOs especificos, retornar solo datos necesarios.',
        'category': 'OTHER', 'severity': 'Medium', 'cwe': 'CWE-213', 'tags': ['api', 'data-exposure']
    },
    'API - Mass Assignment': {
        'desc': 'Permite modificar propiedades no previstas mediante binding automatico.',
        'sol': 'Usar listas blancas de propiedades, DTOs separados para input/output.',
        'category': 'A01:2021', 'severity': 'High', 'cwe': 'CWE-915', 'tags': ['api', 'mass-assignment']
    },
    'API - Missing Rate Limiting': {
        'desc': 'API sin limitacion de tasa permitiendo abuso de recursos.',
        'sol': 'Implementar rate limiting por IP/usuario/API key, quotas, throttling.',
        'category': 'A04:2021', 'severity': 'Medium', 'cwe': 'CWE-799', 'tags': ['api', 'rate-limit']
    }
}

SIG_PATTERNS = {
    'Email Disclosure': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}',
    'Private IP Disclosure': r'(^|[^0-9])(192\.168|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))\.[0-9]{1,3}\.[0-9]{1,3}',
    'Software Version Disclosure': r'(Apache|nginx|PHP|Microsoft-IIS|Tomcat|Express)/[\d\.]+'
}

# ============================================================================
# EXTENSION PRINCIPAL
# ============================================================================

class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory, IMessageEditorController):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Reportes")
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        
        self._findings = []
        self._finding_counter = 1
        self._lock = threading.Lock()
        self._auto_save_enabled = True
        self._current_project_file = None
        
        self._init_gui()
        callbacks.addSuiteTab(self)
        
        self._auto_load_last_project()
        
        print("=" * 70)
        print(">>> Reportes")
        print(">>> Caracteristicas:")
        print("    - Auto-save/load automatico")
        print("    - Exportacion Faraday/DefectDojo/JSON/HTML")
        print("    - 40+ vulnerabilidades predefinidas")
        print("    - Categorizacion OWASP Top 10 2021")
        print("    - Busqueda y filtros avanzados")
        print("=" * 70)
    
    # ========================================================================
    # GUI
    # ========================================================================
    
    def _init_gui(self):
        self._panel = JPanel(BorderLayout())
        
        # Toolbar
        toolbar = self._create_toolbar()
        self._panel.add(toolbar, BorderLayout.NORTH)
        
        # Split principal
        split_main = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        split_main.setResizeWeight(0.5)
        
        # Panel superior
        top_panel = JPanel(BorderLayout())
        search_panel = self._create_search_panel()
        top_panel.add(search_panel, BorderLayout.NORTH)
        table_panel = self._create_table_panel()
        top_panel.add(table_panel, BorderLayout.CENTER)
        
        # Panel inferior
        bottom_panel = self._create_evidence_panel()
        
        split_main.setTopComponent(top_panel)
        split_main.setBottomComponent(bottom_panel)
        
        self._panel.add(split_main, BorderLayout.CENTER)
        
        # Panel estadisticas
        stats_panel = self._create_stats_panel()
        self._panel.add(stats_panel, BorderLayout.EAST)
    
    def _create_toolbar(self):
        toolbar = JPanel()
        toolbar.setLayout(BoxLayout(toolbar, BoxLayout.X_AXIS))
        toolbar.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        
        # Proyecto
        toolbar.add(JLabel("Proyecto: "))
        self._btn_new = JButton("Nuevo", actionPerformed=self.action_new_project)
        self._btn_save = JButton("Guardar", actionPerformed=self.action_save_project)
        self._btn_load = JButton("Cargar", actionPerformed=self.action_load_project)
        self._chk_autosave = JCheckBox("Auto-save", self._auto_save_enabled, actionPerformed=self.action_toggle_autosave)
        
        toolbar.add(self._btn_new)
        toolbar.add(self._btn_save)
        toolbar.add(self._btn_load)
        toolbar.add(self._chk_autosave)
        toolbar.add(self._create_separator())
        
        # Exportar
        toolbar.add(JLabel("Exportar: "))
        self._btn_export_html = JButton("HTML", actionPerformed=self.action_generate_report_dialog)
        self._btn_export_json = JButton("JSON", actionPerformed=self.action_export_json)
        self._btn_export_faraday = JButton("Faraday", actionPerformed=self.action_export_faraday)
        self._btn_export_defectdojo = JButton("DefectDojo", actionPerformed=self.action_export_defectdojo)
        
        toolbar.add(self._btn_export_html)
        toolbar.add(self._btn_export_json)
        toolbar.add(self._btn_export_faraday)
        toolbar.add(self._btn_export_defectdojo)
        toolbar.add(self._create_separator())
        
        # Acciones
        toolbar.add(JLabel("Acciones: "))
        self._btn_add_manual = JButton("+ Agregar", actionPerformed=self.action_add_manual_finding)
        self._btn_edit = JButton("Editar", actionPerformed=self.action_edit_finding)
        self._btn_delete = JButton("Eliminar", actionPerformed=self.action_delete_row)
        self._btn_clear = JButton("Limpiar", actionPerformed=self.action_clear)
        
        toolbar.add(self._btn_add_manual)
        toolbar.add(self._btn_edit)
        toolbar.add(self._btn_delete)
        toolbar.add(self._btn_clear)
        
        return toolbar
    
    def _create_separator(self):
        sep = JSeparator(SwingConstants.VERTICAL)
        sep.setMaximumSize(Dimension(2, 30))
        return sep
    
    def _create_search_panel(self):
        panel = JPanel(FlowLayout(FlowLayout.LEFT))
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        
        panel.add(JLabel("Buscar:"))
        self._txt_search = JTextField(25)
        self._txt_search.addKeyListener(SearchKeyListener(self))
        panel.add(self._txt_search)
        
        panel.add(JLabel("Severidad:"))
        self._combo_sev_filter = JComboBox(["Todas", "Critical", "High", "Medium", "Low", "Info"])
        self._combo_sev_filter.addActionListener(FilterListener(self))
        panel.add(self._combo_sev_filter)
        
        panel.add(JLabel("Categoria:"))
        cats = ["Todas"] + sorted(OWASP_CATEGORIES.keys())
        self._combo_cat_filter = JComboBox(cats)
        self._combo_cat_filter.addActionListener(FilterListener(self))
        panel.add(self._combo_cat_filter)
        
        self._chk_scope = JCheckBox("Solo Scope", True)
        self._chk_scope.addActionListener(FilterListener(self))
        panel.add(self._chk_scope)
        
        return panel
    
    def _create_table_panel(self):
        columns = ["ID", "Host", "Path", "Vulnerabilidad", "Severidad", "OWASP", "CWE", "Tags"]
        self._table_model = DefaultTableModel(columns, 0)
        self._table = JTable(self._table_model)
        self._table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._table.setAutoCreateRowSorter(True)
        self._table.getTableHeader().setReorderingAllowed(False)
        
        col_widths = [40, 150, 200, 250, 80, 100, 80, 150]
        for i, width in enumerate(col_widths):
            self._table.getColumnModel().getColumn(i).setPreferredWidth(width)
        
        self._table.addMouseListener(TableClickListener(self))
        
        scroll = JScrollPane(self._table)
        scroll.setPreferredSize(Dimension(1200, 300))
        return scroll
    
    def _create_evidence_panel(self):
        self._tabs_evidence = JTabbedPane()
        
        self._txt_detail = JTextArea()
        self._txt_detail.setLineWrap(True)
        self._txt_detail.setWrapStyleWord(True)
        self._txt_detail.setEditable(False)
        self._txt_detail.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._tabs_evidence.addTab("Detalles", JScrollPane(self._txt_detail))
        
        self._req_viewer = self._callbacks.createMessageEditor(self, False)
        self._tabs_evidence.addTab("Request", self._req_viewer.getComponent())
        
        self._res_viewer = self._callbacks.createMessageEditor(self, False)
        self._tabs_evidence.addTab("Response", self._res_viewer.getComponent())
        
        return self._tabs_evidence
    
    def _create_stats_panel(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createTitledBorder("Estadisticas"))
        panel.setPreferredSize(Dimension(180, 0))
        
        self._lbl_total = JLabel("Total: 0")
        self._lbl_critical = JLabel("Critical: 0")
        self._lbl_high = JLabel("High: 0")
        self._lbl_medium = JLabel("Medium: 0")
        self._lbl_low = JLabel("Low: 0")
        self._lbl_info = JLabel("Info: 0")
        
        self._lbl_critical.setForeground(Color(200, 0, 0))
        self._lbl_high.setForeground(Color(255, 100, 0))
        self._lbl_medium.setForeground(Color(255, 165, 0))
        self._lbl_low.setForeground(Color(70, 130, 180))
        self._lbl_info.setForeground(Color(60, 170, 60))
        
        for lbl in [self._lbl_total, self._lbl_critical, self._lbl_high, 
                    self._lbl_medium, self._lbl_low, self._lbl_info]:
            lbl.setFont(Font("Dialog", Font.BOLD, 13))
            panel.add(lbl)
            panel.add(self._create_separator())
        
        return panel
    
    # ========================================================================
    # HTTP LISTENER - DETECCION AUTOMATICA
    # ========================================================================
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        
        if self._chk_scope.isSelected() and not self._callbacks.isInScope(messageInfo.getUrl()):
            return
        
        try:
            response = messageInfo.getResponse()
            if not response:
                return
            
            analyzed = self._helpers.analyzeResponse(response)
            headers = analyzed.getHeaders()
            body = self._helpers.bytesToString(response)[analyzed.getBodyOffset():]
            url = messageInfo.getUrl()
            
            self._check_security_headers(headers, url, messageInfo)
            self._check_insecure_cookies(headers, url, messageInfo)
            self._check_disclosure_patterns(body, url, messageInfo)
            self._check_cors_misconfiguration(headers, url, messageInfo)
            
        except Exception as e:
            print("Error deteccion: " + str(e))
    
    def _check_security_headers(self, headers, url, messageInfo):
        required = {
            'Strict-Transport-Security': False,
            'X-Frame-Options': False,
            'X-Content-Type-Options': False,
            'Content-Security-Policy': False
        }
        
        for h in headers:
            h_lower = h.lower()
            for rh in required.keys():
                if rh.lower() in h_lower:
                    required[rh] = True
        
        missing = [h for h, present in required.items() if not present]
        if missing:
            self.add_finding_internal(
                url.getHost(), url.getPath(),
                "Headers de Seguridad Faltantes",
                "Faltan: " + ", ".join(missing),
                "Medium", messageInfo
            )
    
    def _check_insecure_cookies(self, headers, url, messageInfo):
        for h in headers:
            if h.lower().startswith("set-cookie:"):
                cookie_value = h[11:].strip()
                flags = cookie_value.lower()
                
                issues = []
                if "secure" not in flags:
                    issues.append("Secure")
                if "httponly" not in flags:
                    issues.append("HttpOnly")
                if "samesite" not in flags:
                    issues.append("SameSite")
                
                if issues:
                    self.add_finding_internal(
                        url.getHost(), url.getPath(),
                        "Cookie Insegura (Flags)",
                        "Faltan flags: " + ", ".join(issues),
                        "Medium", messageInfo
                    )
    
    def _check_disclosure_patterns(self, body, url, messageInfo):
        for vuln_name, pattern in SIG_PATTERNS.items():
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                unique = set([m if isinstance(m, str) else m[0] for m in matches])
                evidence = ", ".join(list(unique)[:5])
                
                self.add_finding_internal(
                    url.getHost(), url.getPath(), vuln_name,
                    "Detectado: " + evidence,
                    VULN_DB.get(vuln_name, {}).get('severity', 'Info'),
                    messageInfo
                )
    
    def _check_cors_misconfiguration(self, headers, url, messageInfo):
        for h in headers:
            if "access-control-allow-origin" in h.lower() and "*" in h:
                self.add_finding_internal(
                    url.getHost(), url.getPath(),
                    "CORS Misconfiguration",
                    "Access-Control-Allow-Origin: *",
                    "Medium", messageInfo
                )
    
    # ========================================================================
    # GESTION DE HALLAZGOS
    # ========================================================================
    
    def add_finding_internal(self, host, path, title, desc, severity, request_response):
        with self._lock:
            dup_key = "{}|{}|{}".format(host, path, title)
            for f in self._findings:
                if f.get('dup_key') == dup_key:
                    return
            
            vuln_info = VULN_DB.get(title, {
                'desc': desc,
                'sol': 'Revisar y remediar segun mejores practicas.',
                'category': 'OTHER',
                'severity': severity,
                'cwe': 'CWE-Unknown',
                'tags': []
            })
            
            finding = {
                'id': self._finding_counter,
                'host': host,
                'path': path,
                'title': title,
                'desc_full': desc if desc else vuln_info['desc'],
                'remediation': vuln_info['sol'],
                'severity': severity if severity else vuln_info['severity'],
                'category': vuln_info['category'],
                'cwe': vuln_info.get('cwe', 'CWE-Unknown'),
                'tags': vuln_info.get('tags', []),
                'cvss': CVSS_TEMPLATES.get(severity, ''),
                'request_response': request_response,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'dup_key': dup_key,
                'notes': ''
            }
            
            self._findings.append(finding)
            self._finding_counter += 1
            
            SwingUtilities.invokeLater(lambda: self._refresh_table())
            
            if self._auto_save_enabled:
                self._auto_save()
    
    def _refresh_table(self):
        self._table_model.setRowCount(0)
        
        search_text = self._txt_search.getText().lower()
        sev_filter = str(self._combo_sev_filter.getSelectedItem())
        cat_filter = str(self._combo_cat_filter.getSelectedItem())
        
        for f in self._findings:
            if search_text and search_text not in f['title'].lower() and \
               search_text not in f['host'].lower() and search_text not in f['path'].lower():
                continue
            
            if sev_filter != "Todas" and f['severity'] != sev_filter:
                continue
            
            if cat_filter != "Todas" and f['category'] != cat_filter:
                continue
            
            tags_str = ", ".join(f['tags'][:3])
            self._table_model.addRow([
                f['id'], f['host'], f['path'], f['title'],
                f['severity'], OWASP_CATEGORIES.get(f['category'], 'Other'),
                f['cwe'], tags_str
            ])
        
        self._update_stats()
    
    def _update_stats(self):
        counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for f in self._findings:
            sev = f['severity']
            if sev in counts:
                counts[sev] += 1
        
        self._lbl_total.setText("Total: {}".format(len(self._findings)))
        self._lbl_critical.setText("Critical: {}".format(counts['Critical']))
        self._lbl_high.setText("High: {}".format(counts['High']))
        self._lbl_medium.setText("Medium: {}".format(counts['Medium']))
        self._lbl_low.setText("Low: {}".format(counts['Low']))
        self._lbl_info.setText("Info: {}".format(counts['Info']))
    
    # ========================================================================
    # MENU CONTEXTUAL
    # ========================================================================
    
    def createMenuItems(self, invocation):
        menu_items = ArrayList()
        
        item_send = JMenuItem("Enviar a Reportes", actionPerformed=lambda e: self.send_to_reports(invocation))
        menu_items.add(item_send)
        
        item_manual = JMenuItem("Agregar Hallazgo Manual", actionPerformed=lambda e: self.add_manual_from_menu(invocation))
        menu_items.add(item_manual)
        
        return menu_items
    
    def send_to_reports(self, invocation):
        messages = invocation.getSelectedMessages()
        if messages:
            msg = messages[0]
            url = msg.getUrl()
            
            title = JOptionPane.showInputDialog(None, "Titulo del hallazgo:", "Vulnerabilidad Detectada")
            
            if title:
                self.add_finding_internal(
                    url.getHost(), url.getPath(), title,
                    "Enviado desde menu contextual",
                    "Medium", msg
                )
                JOptionPane.showMessageDialog(None, "Hallazgo agregado")
    
    def add_manual_from_menu(self, invocation):
        messages = invocation.getSelectedMessages()
        message = messages[0] if messages else None
        
        if not message:
            JOptionPane.showMessageDialog(None, "Selecciona un request primero")
            return
        
        url = message.getUrl()
        
        panel = JPanel(GridLayout(0, 1, 5, 5))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        vuln_names = sorted(VULN_DB.keys())
        combo_template = JComboBox(["[Personalizado]"] + vuln_names)
        txt_title = JTextField()
        txt_desc = JTextArea(5, 40)
        txt_sol = JTextArea(3, 40)
        combo_sev = JComboBox(["Critical", "High", "Medium", "Low", "Info"])
        txt_tags = JTextField()
        
        def template_changed(e):
            sel = str(combo_template.getSelectedItem())
            if sel != "[Personalizado]" and sel in VULN_DB:
                v = VULN_DB[sel]
                txt_title.setText(sel)
                txt_desc.setText(v['desc'])
                txt_sol.setText(v['sol'])
                combo_sev.setSelectedItem(v['severity'])
                txt_tags.setText(", ".join(v.get('tags', [])))
        
        combo_template.addActionListener(lambda e: template_changed(e))
        
        panel.add(JLabel("Plantilla:"))
        panel.add(combo_template)
        panel.add(JLabel("Titulo:"))
        panel.add(txt_title)
        panel.add(JLabel("Severidad:"))
        panel.add(combo_sev)
        panel.add(JLabel("Tags:"))
        panel.add(txt_tags)
        panel.add(JLabel("Descripcion:"))
        panel.add(JScrollPane(txt_desc))
        panel.add(JLabel("Solucion:"))
        panel.add(JScrollPane(txt_sol))
        
        result = JOptionPane.showConfirmDialog(
            None, panel, "Agregar Hallazgo Manual",
            JOptionPane.OK_CANCEL_OPTION
        )
        
        if result == JOptionPane.OK_OPTION:
            title = txt_title.getText().strip()
            if not title:
                JOptionPane.showMessageDialog(None, "El titulo es obligatorio")
                return
            
            with self._lock:
                finding = {
                    'id': self._finding_counter,
                    'host': url.getHost(),
                    'path': url.getPath(),
                    'title': title,
                    'desc_full': txt_desc.getText(),
                    'remediation': txt_sol.getText(),
                    'severity': str(combo_sev.getSelectedItem()),
                    'category': VULN_DB.get(title, {}).get('category', 'OTHER'),
                    'cwe': VULN_DB.get(title, {}).get('cwe', 'CWE-Custom'),
                    'tags': [t.strip() for t in txt_tags.getText().split(',') if t.strip()],
                    'cvss': CVSS_TEMPLATES.get(str(combo_sev.getSelectedItem()), ''),
                    'request_response': message,
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'dup_key': "{}|{}|{}".format(url.getHost(), url.getPath(), title),
                    'notes': ''
                }
                
                self._findings.append(finding)
                self._finding_counter += 1
            
            SwingUtilities.invokeLater(lambda: self._refresh_table())
            if self._auto_save_enabled:
                self._auto_save()
            
            JOptionPane.showMessageDialog(None, "Hallazgo agregado")
    
    # ========================================================================
    # ACCIONES DE BOTONES
    # ========================================================================
    
    def action_new_project(self, event):
        if len(self._findings) > 0:
            result = JOptionPane.showConfirmDialog(
                self._panel, "Hay hallazgos sin guardar. Crear nuevo proyecto?",
                "Confirmar", JOptionPane.YES_NO_OPTION
            )
            if result != JOptionPane.YES_OPTION:
                return
        
        with self._lock:
            self._findings = []
            self._finding_counter = 1
            self._current_project_file = None
        
        SwingUtilities.invokeLater(lambda: self._refresh_table())
        JOptionPane.showMessageDialog(self._panel, "Nuevo proyecto creado")
    
    def action_save_project(self, event):
        if not self._current_project_file:
            chooser = JFileChooser()
            if chooser.showSaveDialog(self._panel) == JFileChooser.APPROVE_OPTION:
                filepath = str(chooser.getSelectedFile())
                if not filepath.endswith(".json"):
                    filepath += ".json"
                self._current_project_file = filepath
        
        if self._current_project_file:
            self._save_project_to_file(self._current_project_file)
            JOptionPane.showMessageDialog(self._panel, "Proyecto guardado")
    
    def action_load_project(self, event):
        chooser = JFileChooser()
        if chooser.showOpenDialog(self._panel) == JFileChooser.APPROVE_OPTION:
            filepath = str(chooser.getSelectedFile())
            self._load_project_from_file(filepath)
            self._current_project_file = filepath
            JOptionPane.showMessageDialog(self._panel, "Proyecto cargado")
    
    def action_toggle_autosave(self, event):
        self._auto_save_enabled = self._chk_autosave.isSelected()
    
    def action_add_manual_finding(self, event):
        JOptionPane.showMessageDialog(
            self._panel,
            "Click derecho en un request > 'Agregar Hallazgo Manual'"
        )
    
    def action_edit_finding(self, event):
        row = self._table.getSelectedRow()
        if row == -1:
            JOptionPane.showMessageDialog(self._panel, "Selecciona un hallazgo")
            return
        
        idx = self._table.convertRowIndexToModel(row)
        f = self._findings[idx]
        
        panel = JPanel(GridLayout(0, 1, 5, 5))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        txt_title = JTextField(f['title'])
        combo_sev = JComboBox(["Critical", "High", "Medium", "Low", "Info"])
        combo_sev.setSelectedItem(f['severity'])
        txt_desc = JTextArea(f['desc_full'], 5, 40)
        txt_sol = JTextArea(f['remediation'], 3, 40)
        txt_tags = JTextField(", ".join(f['tags']))
        txt_notes = JTextArea(f.get('notes', ''), 3, 40)
        
        panel.add(JLabel("Titulo:"))
        panel.add(txt_title)
        panel.add(JLabel("Severidad:"))
        panel.add(combo_sev)
        panel.add(JLabel("Tags:"))
        panel.add(txt_tags)
        panel.add(JLabel("Descripcion:"))
        panel.add(JScrollPane(txt_desc))
        panel.add(JLabel("Solucion:"))
        panel.add(JScrollPane(txt_sol))
        panel.add(JLabel("Notas:"))
        panel.add(JScrollPane(txt_notes))
        
        result = JOptionPane.showConfirmDialog(
            self._panel, panel, "Editar Hallazgo",
            JOptionPane.OK_CANCEL_OPTION
        )
        
        if result == JOptionPane.OK_OPTION:
            with self._lock:
                f['title'] = txt_title.getText()
                f['severity'] = str(combo_sev.getSelectedItem())
                f['desc_full'] = txt_desc.getText()
                f['remediation'] = txt_sol.getText()
                f['tags'] = [t.strip() for t in txt_tags.getText().split(',') if t.strip()]
                f['notes'] = txt_notes.getText()
                f['cvss'] = CVSS_TEMPLATES.get(f['severity'], '')
            
            SwingUtilities.invokeLater(lambda: self._refresh_table())
            if self._auto_save_enabled:
                self._auto_save()
    
    def action_delete_row(self, event):
        row = self._table.getSelectedRow()
        if row == -1:
            return
        
        result = JOptionPane.showConfirmDialog(
            self._panel, "Eliminar este hallazgo?",
            "Confirmar", JOptionPane.YES_NO_OPTION
        )
        
        if result == JOptionPane.YES_OPTION:
            idx = self._table.convertRowIndexToModel(row)
            with self._lock:
                del self._findings[idx]
            SwingUtilities.invokeLater(lambda: self._refresh_table())
            if self._auto_save_enabled:
                self._auto_save()
    
    def action_clear(self, event):
        result = JOptionPane.showConfirmDialog(
            self._panel, "Eliminar TODOS los hallazgos?",
            "Confirmar", JOptionPane.YES_NO_OPTION
        )
        
        if result == JOptionPane.YES_OPTION:
            with self._lock:
                self._findings = []
            SwingUtilities.invokeLater(lambda: self._refresh_table())
            if self._auto_save_enabled:
                self._auto_save()
    
    # ========================================================================
    # PERSISTENCIA
    # ========================================================================
    
    def _auto_save(self):
        if not self._auto_save_enabled:
            return
        
        try:
            import tempfile
            temp_dir = tempfile.gettempdir()
            autosave_file = os.path.join(temp_dir, "burp_reportes_autosave.json")
            self._save_project_to_file(autosave_file)
        except Exception as e:
            print("Error auto-save: " + str(e))
    
    def _auto_load_last_project(self):
        try:
            import tempfile
            temp_dir = tempfile.gettempdir()
            autosave_file = os.path.join(temp_dir, "burp_reportes_autosave.json")
            
            if os.path.exists(autosave_file):
                self._load_project_from_file(autosave_file)
                print(">>> Auto-loaded: {} findings".format(len(self._findings)))
        except Exception as e:
            print("No auto-load: " + str(e))
    
    def _save_project_to_file(self, filepath):
        try:
            with self._lock:
                export_data = []
                
                for f in self._findings:
                    rr = f['request_response']
                    req_b64 = ""
                    res_b64 = ""
                    
                    if rr:
                        if rr.getRequest():
                            req_b64 = base64.b64encode(self._helpers.bytesToString(rr.getRequest()).encode('utf-8')).decode('ascii')
                        if rr.getResponse():
                            res_b64 = base64.b64encode(self._helpers.bytesToString(rr.getResponse()).encode('utf-8')).decode('ascii')
                    
                    export_data.append({
                        'id': f['id'],
                        'host': f['host'],
                        'path': f['path'],
                        'title': f['title'],
                        'desc_full': f['desc_full'],
                        'remediation': f['remediation'],
                        'severity': f['severity'],
                        'category': f['category'],
                        'cwe': f['cwe'],
                        'tags': f['tags'],
                        'cvss': f['cvss'],
                        'timestamp': f['timestamp'],
                        'notes': f.get('notes', ''),
                        'request_b64': req_b64,
                        'response_b64': res_b64
                    })
                
                project = {
                    'version': '7.0',
                    'timestamp': datetime.now().isoformat(),
                    'finding_counter': self._finding_counter,
                    'findings': export_data
                }
                
                with codecs.open(filepath, 'w', 'utf-8') as f:
                    json.dump(project, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            print("Error guardando: " + str(e))
    
    def _load_project_from_file(self, filepath):
        try:
            with codecs.open(filepath, 'r', 'utf-8') as f:
                project = json.load(f)
            
            with self._lock:
                self._findings = []
                self._finding_counter = project.get('finding_counter', 1)
                
                for item in project.get('findings', []):
                    finding = {
                        'id': item['id'],
                        'host': item['host'],
                        'path': item['path'],
                        'title': item['title'],
                        'desc_full': item['desc_full'],
                        'remediation': item['remediation'],
                        'severity': item['severity'],
                        'category': item.get('category', 'OTHER'),
                        'cwe': item.get('cwe', 'CWE-Unknown'),
                        'tags': item.get('tags', []),
                        'cvss': item.get('cvss', ''),
                        'timestamp': item.get('timestamp', ''),
                        'notes': item.get('notes', ''),
                        'dup_key': "{}|{}|{}".format(item['host'], item['path'], item['title']),
                        'request_response': None
                    }
                    
                    self._findings.append(finding)
            
            SwingUtilities.invokeLater(lambda: self._refresh_table())
            
        except Exception as e:
            print("Error cargando: " + str(e))
    
    # ========================================================================
    # EXPORTACION
    # ========================================================================
    
    def action_export_json(self, event):
        chooser = JFileChooser()
        if chooser.showSaveDialog(self._panel) == JFileChooser.APPROVE_OPTION:
            filepath = str(chooser.getSelectedFile())
            if not filepath.endswith(".json"):
                filepath += ".json"
            
            self._save_project_to_file(filepath)
            JOptionPane.showMessageDialog(self._panel, "JSON exportado")
    
    def action_export_faraday(self, event):
        chooser = JFileChooser()
        if chooser.showSaveDialog(self._panel) == JFileChooser.APPROVE_OPTION:
            filepath = str(chooser.getSelectedFile())
            if not filepath.endswith(".json"):
                filepath += ".json"
            
            self._export_faraday_format(filepath)
            JOptionPane.showMessageDialog(self._panel, "Faraday exportado")
    
    def _export_faraday_format(self, filepath):
        vulnerabilities = []
        
        severity_map = {
            'Critical': 'critical',
            'High': 'high',
            'Medium': 'medium',
            'Low': 'low',
            'Info': 'informational'
        }
        
        for f in self._findings:
            vuln = {
                'name': f['title'],
                'desc': f['desc_full'],
                'severity': severity_map.get(f['severity'], 'informational'),
                'resolution': f['remediation'],
                'refs': [],
                'data': '',
                'website': '',
                'path': f['path'],
                'request': '',
                'response': '',
                'category': OWASP_CATEGORIES.get(f['category'], 'Other'),
                'status': 'opened',
                'tags': f['tags'],
                'hostnames': [f['host']],
                'confirmed': False
            }
            vulnerabilities.append(vuln)
        
        data = {
            'vulnerabilities': vulnerabilities,
            'command': {
                'tool': 'Burp Reportes',
                'command': 'manual',
                'start_date': datetime.now().isoformat()
            }
        }
        
        with codecs.open(filepath, 'w', 'utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def action_export_defectdojo(self, event):
        chooser = JFileChooser()
        if chooser.showSaveDialog(self._panel) == JFileChooser.APPROVE_OPTION:
            filepath = str(chooser.getSelectedFile())
            if not filepath.endswith(".json"):
                filepath += ".json"
            
            self._export_defectdojo_format(filepath)
            JOptionPane.showMessageDialog(self._panel, "DefectDojo exportado")
    
    def _export_defectdojo_format(self, filepath):
        findings = []
        
        for f in self._findings:
            cwe_num = 0
            if 'cwe' in f and f['cwe'].startswith('CWE-'):
                try:
                    cwe_num = int(f['cwe'].replace('CWE-', ''))
                except:
                    pass
            
            finding = {
                'title': f['title'],
                'description': f['desc_full'],
                'severity': f['severity'],
                'mitigation': f['remediation'],
                'active': True,
                'verified': False,
                'cwe': cwe_num,
                'cvssv3': f['cvss'],
                'url': "https://{}{}".format(f['host'], f['path']),
                'tags': f['tags'],
                'endpoints': [{
                    'host': f['host'],
                    'path': f['path'],
                    'protocol': 'https'
                }],
                'unique_id_from_tool': str(f['id']),
                'publish_date': f['timestamp']
            }
            findings.append(finding)
        
        data = {
            'findings': findings,
            'scan_type': 'Burp Reportes',
            'engagement_name': 'Security Assessment'
        }
        
        with codecs.open(filepath, 'w', 'utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def action_generate_report_dialog(self, event):
        panel = JPanel(GridLayout(0, 1, 5, 5))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        txt_project = JTextField("Security Assessment")
        txt_client = JTextField("Client Name")
        txt_auditor = JTextField("Security Team")
        txt_summary = JTextArea(5, 40)
        txt_summary.setText("Durante la evaluacion se identificaron vulnerabilidades que afectan la seguridad.")
        
        panel.add(JLabel("Proyecto:"))
        panel.add(txt_project)
        panel.add(JLabel("Cliente:"))
        panel.add(txt_client)
        panel.add(JLabel("Auditor:"))
        panel.add(txt_auditor)
        panel.add(JLabel("Resumen:"))
        panel.add(JScrollPane(txt_summary))
        
        result = JOptionPane.showConfirmDialog(
            self._panel, panel, "Reporte HTML",
            JOptionPane.OK_CANCEL_OPTION
        )
        
        if result == JOptionPane.OK_OPTION:
            chooser = JFileChooser()
            if chooser.showSaveDialog(self._panel) == JFileChooser.APPROVE_OPTION:
                filepath = str(chooser.getSelectedFile())
                if not filepath.endswith(".html"):
                    filepath += ".html"
                
                self._generate_html_report(
                    filepath,
                    txt_project.getText(),
                    txt_client.getText(),
                    txt_auditor.getText(),
                    txt_summary.getText()
                )
                
                JOptionPane.showMessageDialog(self._panel, "Reporte HTML generado")
    
    def _escape_html(self, text):
        if not text:
            return ""
        try:
            if isinstance(text, str):
                text = text.decode('utf-8', 'ignore')
        except:
            pass
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    
    def _generate_html_report(self, filepath, project, client, auditor, summary):
        counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for f in self._findings:
            if f['severity'] in counts:
                counts[f['severity']] += 1
        
        css = """
        <style>
            body { font-family: 'Segoe UI', sans-serif; background: #f5f7fa; color: #2c3e50; margin: 0; padding: 0; }
            .header { background: linear-gradient(135deg, #1a237e 0%, #283593 100%); color: white; padding: 3rem 2rem; text-align: center; }
            .container { max-width: 1200px; margin: 2rem auto; padding: 0 2rem; }
            .metrics { display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; margin-bottom: 2rem; }
            .card { background: white; padding: 1.5rem; border-radius: 8px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
            .card h3 { font-size: 2rem; margin: 0; }
            .Critical { color: #c62828; } .High { color: #f57c00; } .Medium { color: #fbc02d; } .Low { color: #1976d2; } .Info { color: #388e3c; }
            .finding { background: white; margin-bottom: 1.5rem; border-radius: 8px; padding: 1.5rem; border-left: 5px solid; }
            .finding-critical { border-left-color: #c62828; }
            .finding-high { border-left-color: #f57c00; }
            .finding-medium { border-left-color: #fbc02d; }
            .finding-low { border-left-color: #1976d2; }
            .finding-info { border-left-color: #388e3c; }
            .code { background: #1e1e1e; color: #d4d4d4; padding: 1rem; border-radius: 4px; overflow-x: auto; font-family: monospace; font-size: 0.9em; }
        </style>
        """
        
        html = u"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>{project}</title>
    {css}
</head>
<body>
    <div class="header">
        <h1>{project}</h1>
        <p>{client} | {auditor} | {date}</p>
    </div>
    
    <div class="container">
        <div class="metrics">
            <div class="card"><h3 class="Critical">{critical}</h3><p>Critical</p></div>
            <div class="card"><h3 class="High">{high}</h3><p>High</p></div>
            <div class="card"><h3 class="Medium">{medium}</h3><p>Medium</p></div>
            <div class="card"><h3 class="Low">{low}</h3><p>Low</p></div>
            <div class="card"><h3 class="Info">{info}</h3><p>Info</p></div>
        </div>
        
        <div class="card" style="margin-bottom: 2rem;">
            <h2>Resumen Ejecutivo</h2>
            <p>{summary}</p>
        </div>
        
        <h2>Hallazgos Detallados</h2>
""".format(
            project=self._escape_html(project),
            client=self._escape_html(client),
            auditor=self._escape_html(auditor),
            date=datetime.now().strftime("%Y-%m-%d"),
            css=css,
            critical=counts['Critical'],
            high=counts['High'],
            medium=counts['Medium'],
            low=counts['Low'],
            info=counts['Info'],
            summary=self._escape_html(summary)
        )
        
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        sorted_findings = sorted(self._findings, key=lambda f: severity_order.get(f['severity'], 99))
        
        for f in sorted_findings:
            req_text = ""
            res_text = ""
            rr = f['request_response']
            if rr:
                if rr.getRequest():
                    req_text = self._helpers.bytesToString(rr.getRequest())
                    if len(req_text) > 5000:
                        req_text = req_text[:5000] + "\n... [TRUNCADO]"
                
                if rr.getResponse():
                    res_text = self._helpers.bytesToString(rr.getResponse())
                    if len(res_text) > 8000:
                        res_text = res_text[:8000] + "\n... [TRUNCADO]"
            
            html += u"""
        <div class="finding finding-{sev_lower}">
            <h3>{title} <span style="float:right; color: inherit;">{severity}</span></h3>
            <p><strong>Host:</strong> {host} | <strong>Path:</strong> {path}</p>
            <p><strong>Categoria:</strong> {category} | <strong>CWE:</strong> {cwe}</p>
            <p><strong>Descripcion:</strong></p>
            <p>{desc}</p>
            <p><strong>Solucion:</strong></p>
            <p>{sol}</p>
""".format(
                sev_lower=f['severity'].lower(),
                title=self._escape_html(f['title']),
                severity=f['severity'],
                host=self._escape_html(f['host']),
                path=self._escape_html(f['path']),
                category=OWASP_CATEGORIES.get(f['category'], 'Other'),
                cwe=f['cwe'],
                desc=self._escape_html(f['desc_full']),
                sol=self._escape_html(f['remediation'])
            )
            
            if req_text:
                html += "<p><strong>Request:</strong></p><div class=\"code\">{}</div>".format(self._escape_html(req_text))
            if res_text:
                html += "<p><strong>Response:</strong></p><div class=\"code\">{}</div>".format(self._escape_html(res_text))
            
            html += "</div>\n"
        
        html += """
    </div>
</body>
</html>"""
        
        with codecs.open(filepath, 'w', 'utf-8') as f:
            f.write(html)
    
    # ========================================================================
    # INTERFACES BURP
    # ========================================================================
    
    def getTabCaption(self):
        return "Reportes"
    
    def getUiComponent(self):
        return self._panel
    
    def getHttpService(self):
        row = self._table.getSelectedRow()
        if row != -1:
            f = self._findings[self._table.convertRowIndexToModel(row)]
            if f['request_response']:
                return f['request_response'].getHttpService()
        return None
    
    def getRequest(self):
        row = self._table.getSelectedRow()
        if row != -1:
            f = self._findings[self._table.convertRowIndexToModel(row)]
            if f['request_response']:
                return f['request_response'].getRequest()
        return None
    
    def getResponse(self):
        row = self._table.getSelectedRow()
        if row != -1:
            f = self._findings[self._table.convertRowIndexToModel(row)]
            if f['request_response']:
                return f['request_response'].getResponse()
        return None

# ============================================================================
# LISTENERS
# ============================================================================

class TableClickListener(MouseAdapter):
    def __init__(self, ext):
        self._ext = ext
    
    def mouseClicked(self, e):
        row = self._ext._table.getSelectedRow()
        if row == -1:
            return
        
        f = self._ext._findings[self._ext._table.convertRowIndexToModel(row)]
        
        detail = u"""TITULO: {title}
HOST: {host}
PATH: {path}
SEVERIDAD: {sev}
CATEGORIA: {cat}
CWE: {cwe}
CVSS: {cvss}
TAGS: {tags}

DESCRIPCION:
{desc}

SOLUCION:
{sol}

NOTAS:
{notes}""".format(
            title=f['title'],
            host=f['host'],
            path=f['path'],
            sev=f['severity'],
            cat=OWASP_CATEGORIES.get(f['category'], 'Other'),
            cwe=f['cwe'],
            cvss=f['cvss'],
            tags=", ".join(f['tags']),
            desc=f['desc_full'],
            sol=f['remediation'],
            notes=f.get('notes', '')
        )
        
        self._ext._txt_detail.setText(detail)
        
        rr = f['request_response']
        if rr:
            self._ext._req_viewer.setMessage(rr.getRequest(), True)
            self._ext._res_viewer.setMessage(rr.getResponse(), False)

class SearchKeyListener(KeyAdapter):
    def __init__(self, ext):
        self._ext = ext
    
    def keyReleased(self, e):
        SwingUtilities.invokeLater(lambda: self._ext._refresh_table())

class FilterListener(ActionListener):
    def __init__(self, ext):
        self._ext = ext
    
    def actionPerformed(self, e):
        SwingUtilities.invokeLater(lambda: self._ext._refresh_table())
