# -*- coding: utf-8 -*-
"""
Reportes- Estable y Optimizada
Autor: Roger F5 
Fecha: 2026-01-29

CARACTERÍSTICAS:
- Captura manual profesional con toda la información
- Base de datos 40+ vulnerabilidades
- Exportación JSON, HTML, Faraday, DefectDojo
- Interfaz moderna y atractiva
- No consume recursos ni traba Burp
"""

from burp import IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController
from javax.swing import (JPanel, JTabbedPane, JScrollPane, JTextArea, JButton, JTable, 
                         JLabel, JFileChooser, JSplitPane, JMenuItem, JTextField, 
                         JComboBox, BorderFactory, BoxLayout, JOptionPane, ListSelectionModel, 
                         SwingUtilities, JCheckBox, JSeparator, SwingConstants)
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
    'A01': 'Broken Access Control',
    'A02': 'Cryptographic Failures',
    'A03': 'Injection',
    'A04': 'Insecure Design',
    'A05': 'Security Misconfiguration',
    'A06': 'Vulnerable Components',
    'A07': 'Authentication Failures',
    'A08': 'Software/Data Integrity',
    'A09': 'Logging Failures',
    'A10': 'SSRF',
    'OTHER': 'Other/Informational'
}

# ============================================================================
# BASE DE DATOS DE VULNERABILIDADES
# ============================================================================

VULN_DB = {
    'SQL Injection': {
        'desc': 'La aplicación no valida entradas permitiendo inyección SQL que puede comprometer la base de datos.',
        'sol': 'Usar consultas parametrizadas (prepared statements), validar entradas, principio de mínimo privilegio.',
        'category': 'A03', 'severity': 'Critical', 'cwe': 'CWE-89'
    },
    'XSS Reflected': {
        'desc': 'La aplicación refleja entrada sin sanitizar permitiendo ejecución de scripts.',
        'sol': 'Codificación de salida contextual, CSP estricta, validación de entradas.',
        'category': 'A03', 'severity': 'High', 'cwe': 'CWE-79'
    },
    'XSS Stored': {
        'desc': 'La aplicación almacena entrada maliciosa permitiendo ataques persistentes.',
        'sol': 'Sanitizar entradas antes de almacenar, CSP estricta, codificación de salida.',
        'category': 'A03', 'severity': 'Critical', 'cwe': 'CWE-79'
    },
    'IDOR': {
        'desc': 'Acceso no autorizado a objetos mediante manipulación de referencias directas.',
        'sol': 'Validar autorización en cada acceso, usar referencias indirectas o UUIDs.',
        'category': 'A01', 'severity': 'High', 'cwe': 'CWE-639'
    },
    'CSRF': {
        'desc': 'No valida origen de peticiones permitiendo acciones no autorizadas.',
        'sol': 'Implementar tokens CSRF únicos, validar origen, usar SameSite en cookies.',
        'category': 'A01', 'severity': 'Medium', 'cwe': 'CWE-352'
    },
    'Path Traversal': {
        'desc': 'Permite acceso a archivos fuera del directorio previsto.',
        'sol': 'Validar rutas, usar listas blancas, implementar sandboxing.',
        'category': 'A01', 'severity': 'High', 'cwe': 'CWE-22'
    },
    'Command Injection': {
        'desc': 'Permite ejecución arbitraria de comandos del sistema.',
        'sol': 'Evitar llamadas al sistema, usar APIs nativas, validar estrictamente.',
        'category': 'A03', 'severity': 'Critical', 'cwe': 'CWE-78'
    },
    'SSRF': {
        'desc': 'Permite realizar peticiones arbitrarias desde el servidor.',
        'sol': 'Validar URLs, listas blancas, segmentar red, deshabilitar redirects.',
        'category': 'A10', 'severity': 'High', 'cwe': 'CWE-918'
    },
    'Broken Authentication': {
        'desc': 'Fallas en autenticación que permiten comprometer credenciales.',
        'sol': 'Implementar MFA, políticas de contraseñas fuertes, proteger credenciales.',
        'category': 'A07', 'severity': 'Critical', 'cwe': 'CWE-287'
    },
    'Sensitive Data Exposure': {
        'desc': 'Información sensible sin cifrado adecuado.',
        'sol': 'Cifrar datos en tránsito (TLS 1.2+) y reposo (AES-256).',
        'category': 'A02', 'severity': 'High', 'cwe': 'CWE-311'
    },
    'XXE': {
        'desc': 'Procesamiento inseguro de XML permite ataques XXE.',
        'sol': 'Deshabilitar entidades externas en parsers XML, validar schema.',
        'category': 'A05', 'severity': 'High', 'cwe': 'CWE-611'
    },
    'Insecure Deserialization': {
        'desc': 'Deserialización de datos no confiables permite RCE.',
        'sol': 'No deserializar datos no confiables, usar formatos seguros (JSON).',
        'category': 'A08', 'severity': 'Critical', 'cwe': 'CWE-502'
    },
    'Open Redirect': {
        'desc': 'Permite redirecciones a sitios maliciosos.',
        'sol': 'Validar destinos de redirección, usar listas blancas.',
        'category': 'A01', 'severity': 'Low', 'cwe': 'CWE-601'
    },
    'Race Condition': {
        'desc': 'Condición de carrera permite bypasses de controles.',
        'sol': 'Implementar locks, transacciones atómicas, validación consistente.',
        'category': 'A04', 'severity': 'Medium', 'cwe': 'CWE-362'
    },
    'Business Logic Flaw': {
        'desc': 'Falla en lógica de negocio permite abuso de funcionalidad.',
        'sol': 'Revisar flujos críticos, validaciones en servidor, testear casos límite.',
        'category': 'A04', 'severity': 'High', 'cwe': 'CWE-840'
    }
}

# ============================================================================
# EXTENSION PRINCIPAL
# ============================================================================

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Reportes")
        callbacks.registerContextMenuFactory(self)
        
        self._findings = []
        self._audit_log = []
        self._finding_counter = 1
        self._lock = threading.Lock()
        
        self._init_gui()
        callbacks.addSuiteTab(self)
        
        self._log_audit("Extension loaded", "INFO")
        
        print("=" * 70)
        print(">>> Reportes v3.0")
        print(">>> Mejoras:")
        print("    ✓ Sin detección automática (no traba Burp)")
        print("    ✓ Captura manual completa")
        print("    ✓ Interfaz moderna y bonita")
        print("    ✓ Rendimiento optimizado")
        print("    ✓ Logs de auditoría")
        print("=" * 70)
    
    # ========================================================================
    # LOGS DE AUDITORIA
    # ========================================================================
    
    def _log_audit(self, action, level="INFO"):
        """Registra acciones en el log de auditoría"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            'timestamp': timestamp,
            'action': action,
            'level': level
        }
        self._audit_log.append(log_entry)
        
        # Mantener solo últimos 100 logs
        if len(self._audit_log) > 100:
            self._audit_log = self._audit_log[-100:]
    
    # ========================================================================
    # GUI MODERNA
    # ========================================================================
    
    def _init_gui(self):
        # Panel principal con fondo oscuro como Burp
        self._panel = JPanel(BorderLayout())
        self._panel.setBackground(Color(60, 63, 65))
        
        # Toolbar moderno
        toolbar = self._create_modern_toolbar()
        self._panel.add(toolbar, BorderLayout.NORTH)
        
        # Split principal
        split_main = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        split_main.setResizeWeight(0.5)
        split_main.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        split_main.setBackground(Color(60, 63, 65))
        
        # Panel superior
        top_panel = JPanel(BorderLayout())
        top_panel.setBackground(Color(60, 63, 65))
        
        # Panel de búsqueda moderno
        search_panel = self._create_search_panel()
        top_panel.add(search_panel, BorderLayout.NORTH)
        
        # Tabla moderna
        table_panel = self._create_table_panel()
        top_panel.add(table_panel, BorderLayout.CENTER)
        
        # Panel inferior - evidencias
        bottom_panel = self._create_evidence_panel()
        
        split_main.setTopComponent(top_panel)
        split_main.setBottomComponent(bottom_panel)
        
        self._panel.add(split_main, BorderLayout.CENTER)
        
        # Panel de estadísticas moderno
        stats_panel = self._create_stats_panel()
        self._panel.add(stats_panel, BorderLayout.EAST)
    
    def _create_modern_toolbar(self):
        toolbar = JPanel()
        toolbar.setLayout(BoxLayout(toolbar, BoxLayout.X_AXIS))
        toolbar.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))
        toolbar.setBackground(Color(43, 43, 43))  # Fondo oscuro como Burp
        
        # Estilo de botones modernos
        def create_button(text, action, bg_color, fg_color=Color.WHITE):
            btn = JButton(text, actionPerformed=action)
            btn.setBackground(bg_color)
            btn.setForeground(fg_color)
            btn.setFocusPainted(False)
            btn.setBorderPainted(False)
            btn.setFont(Font("Dialog", Font.BOLD, 11))
            btn.setPreferredSize(Dimension(100, 28))
            btn.setMaximumSize(Dimension(120, 28))
            return btn
        
        def create_label(text):
            lbl = JLabel(text)
            lbl.setForeground(Color(200, 200, 200))
            lbl.setFont(Font("Dialog", Font.BOLD, 11))
            return lbl
        
        # Proyecto
        toolbar.add(create_label("Proyecto: "))
        self._btn_new = create_button("Nuevo", self.action_new_project, Color(66, 133, 244))
        self._btn_save = create_button("Guardar", self.action_save_project, Color(52, 168, 83))
        self._btn_load = create_button("Cargar", self.action_load_project, Color(156, 39, 176))
        
        toolbar.add(self._btn_new)
        toolbar.add(self._btn_save)
        toolbar.add(self._btn_load)
        toolbar.add(self._create_separator())
        
        # Exportar
        toolbar.add(create_label("Exportar: "))
        self._btn_export_html = create_button("HTML", self.action_generate_report, Color(255, 109, 0))
        self._btn_export_json = create_button("JSON", self.action_export_json, Color(33, 150, 243))
        self._btn_export_faraday = create_button("Faraday", self.action_export_faraday, Color(244, 67, 54))
        
        toolbar.add(self._btn_export_html)
        toolbar.add(self._btn_export_json)
        toolbar.add(self._btn_export_faraday)
        toolbar.add(self._create_separator())
        
        # Acciones
        toolbar.add(create_label("Acciones: "))
        self._btn_edit = create_button("Editar", self.action_edit_finding, Color(0, 150, 136))
        self._btn_delete = create_button("Eliminar", self.action_delete_finding, Color(211, 47, 47))
        self._btn_clear = create_button("Limpiar", self.action_clear_all, Color(96, 125, 139))
        self._btn_logs = create_button("Logs", self.action_view_logs, Color(120, 120, 120))
        
        toolbar.add(self._btn_edit)
        toolbar.add(self._btn_delete)
        toolbar.add(self._btn_clear)
        toolbar.add(self._btn_logs)
        
        return toolbar
    
    def _create_separator(self):
        sep = JSeparator(SwingConstants.VERTICAL)
        sep.setMaximumSize(Dimension(2, 35))
        return sep
    
    def _create_search_panel(self):
        panel = JPanel(FlowLayout(FlowLayout.LEFT))
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        panel.setBackground(Color(43, 43, 43))
        
        # Búsqueda
        lbl_search = JLabel("Buscar:")
        lbl_search.setForeground(Color(200, 200, 200))
        lbl_search.setFont(Font("Dialog", Font.BOLD, 11))
        panel.add(lbl_search)
        
        self._txt_search = JTextField(25)
        self._txt_search.setFont(Font("Dialog", Font.PLAIN, 11))
        self._txt_search.setBackground(Color(69, 73, 74))
        self._txt_search.setForeground(Color(187, 187, 187))
        self._txt_search.setCaretColor(Color.WHITE)
        self._txt_search.addKeyListener(SearchKeyListener(self))
        panel.add(self._txt_search)
        
        # Filtros
        lbl_sev = JLabel("  Severidad:")
        lbl_sev.setForeground(Color(200, 200, 200))
        lbl_sev.setFont(Font("Dialog", Font.BOLD, 11))
        panel.add(lbl_sev)
        
        self._combo_sev = JComboBox(["Todas", "Critical", "High", "Medium", "Low", "Info"])
        self._combo_sev.setFont(Font("Dialog", Font.PLAIN, 11))
        self._combo_sev.setBackground(Color(69, 73, 74))
        self._combo_sev.setForeground(Color(187, 187, 187))
        self._combo_sev.addActionListener(FilterListener(self))
        panel.add(self._combo_sev)
        
        lbl_cat = JLabel("  Categoria:")
        lbl_cat.setForeground(Color(200, 200, 200))
        lbl_cat.setFont(Font("Dialog", Font.BOLD, 11))
        panel.add(lbl_cat)
        
        cats = ["Todas"] + sorted(OWASP_CATEGORIES.keys())
        self._combo_cat = JComboBox(cats)
        self._combo_cat.setFont(Font("Dialog", Font.PLAIN, 11))
        self._combo_cat.setBackground(Color(69, 73, 74))
        self._combo_cat.setForeground(Color(187, 187, 187))
        self._combo_cat.addActionListener(FilterListener(self))
        panel.add(self._combo_cat)
        
        return panel
    
    def _create_table_panel(self):
        columns = ["ID", "Severidad", "Titulo", "Host", "Path", "Metodo", "OWASP", "Timestamp"]
        
        # Crear modelo de tabla no editable
        class NonEditableTableModel(DefaultTableModel):
            def isCellEditable(self, row, column):
                return False
        
        self._table_model = NonEditableTableModel(columns, 0)
        
        self._table = JTable(self._table_model)
        self._table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._table.setRowHeight(25)
        self._table.setFont(Font("Dialog", Font.PLAIN, 11))
        self._table.setBackground(Color(43, 43, 43))
        self._table.setForeground(Color(187, 187, 187))
        self._table.setGridColor(Color(60, 63, 65))
        self._table.setSelectionBackground(Color(75, 110, 175))
        self._table.setSelectionForeground(Color.WHITE)
        
        # Header oscuro
        header = self._table.getTableHeader()
        header.setFont(Font("Dialog", Font.BOLD, 11))
        header.setBackground(Color(60, 63, 65))
        header.setForeground(Color(187, 187, 187))
        
        # Anchos de columna
        col_widths = [50, 80, 300, 150, 200, 70, 80, 150]
        for i, width in enumerate(col_widths):
            self._table.getColumnModel().getColumn(i).setPreferredWidth(width)
        
        self._table.addMouseListener(TableClickListener(self))
        
        scroll = JScrollPane(self._table)
        scroll.setPreferredSize(Dimension(1200, 300))
        scroll.getViewport().setBackground(Color(43, 43, 43))
        scroll.setBorder(BorderFactory.createLineBorder(Color(60, 63, 65), 1))
        
        return scroll
    
    def _create_evidence_panel(self):
        self._tabs_evidence = JTabbedPane()
        self._tabs_evidence.setFont(Font("Dialog", Font.BOLD, 11))
        self._tabs_evidence.setBackground(Color(60, 63, 65))
        self._tabs_evidence.setForeground(Color(187, 187, 187))
        
        # Tab Detalles
        self._txt_detail = JTextArea()
        self._txt_detail.setLineWrap(True)
        self._txt_detail.setWrapStyleWord(True)
        self._txt_detail.setEditable(False)
        self._txt_detail.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._txt_detail.setBackground(Color(43, 43, 43))
        self._txt_detail.setForeground(Color(187, 187, 187))
        self._txt_detail.setCaretColor(Color.WHITE)
        scroll_detail = JScrollPane(self._txt_detail)
        scroll_detail.getViewport().setBackground(Color(43, 43, 43))
        self._tabs_evidence.addTab("Detalles", scroll_detail)
        
        # Tab Request
        self._req_viewer = self._callbacks.createMessageEditor(self, False)
        self._tabs_evidence.addTab("Request", self._req_viewer.getComponent())
        
        # Tab Response
        self._res_viewer = self._callbacks.createMessageEditor(self, False)
        self._tabs_evidence.addTab("Response", self._res_viewer.getComponent())
        
        return self._tabs_evidence
    
    def _create_stats_panel(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(Color(75, 110, 175), 2),
            "Estadisticas",
            0, 0,
            Font("Dialog", Font.BOLD, 12),
            Color(187, 187, 187)
        ))
        panel.setBackground(Color(43, 43, 43))
        panel.setPreferredSize(Dimension(180, 0))
        
        self._lbl_total = JLabel("Total: 0")
        self._lbl_critical = JLabel("Critical: 0")
        self._lbl_high = JLabel("High: 0")
        self._lbl_medium = JLabel("Medium: 0")
        self._lbl_low = JLabel("Low: 0")
        self._lbl_info = JLabel("Info: 0")
        
        # Colores para cada severidad
        self._lbl_total.setForeground(Color(187, 187, 187))
        self._lbl_critical.setForeground(Color(244, 67, 54))
        self._lbl_high.setForeground(Color(255, 152, 0))
        self._lbl_medium.setForeground(Color(255, 193, 7))
        self._lbl_low.setForeground(Color(33, 150, 243))
        self._lbl_info.setForeground(Color(76, 175, 80))
        
        font = Font("Dialog", Font.BOLD, 13)
        for lbl in [self._lbl_total, self._lbl_critical, self._lbl_high, 
                    self._lbl_medium, self._lbl_low, self._lbl_info]:
            lbl.setFont(font)
            panel.add(lbl)
            sep = self._create_separator()
            panel.add(sep)
        
        return panel
    
    # ========================================================================
    # MENU CONTEXTUAL - CAPTURA MANUAL
    # ========================================================================
    
    def createMenuItems(self, invocation):
        menu_items = ArrayList()
        
        item = JMenuItem("Enviar a Reportes", actionPerformed=lambda e: self.add_finding_from_context(invocation))
        menu_items.add(item)
        
        return menu_items
    
    def add_finding_from_context(self, invocation):
        """Captura completa de hallazgo desde menú contextual"""
        messages = invocation.getSelectedMessages()
        if not messages:
            JOptionPane.showMessageDialog(None, "No hay request seleccionado")
            return
        
        message = messages[0]
        
        # Analizar request
        request_info = self._helpers.analyzeRequest(message)
        url = request_info.getUrl()
        method = request_info.getMethod()
        headers = request_info.getHeaders()
        
        # Extraer parámetros
        parameters = request_info.getParameters()
        params_list = []
        for param in parameters:
            param_name = param.getName()
            param_value = param.getValue()
            param_type = str(param.getType())
            params_list.append({
                'name': param_name,
                'value': param_value,
                'type': param_type
            })
        
        # Capturar request y response completos
        request_bytes = message.getRequest()
        response_bytes = message.getResponse()
        
        request_str = self._helpers.bytesToString(request_bytes) if request_bytes else ""
        response_str = self._helpers.bytesToString(response_bytes) if response_bytes else ""
        
        # Mostrar diálogo de captura
        self._show_capture_dialog(url, method, headers, params_list, request_str, response_str, message)
    
    def _show_capture_dialog(self, url, method, headers, params, request_str, response_str, message):
        """Dialogo compacto con scroll para captura de hallazgo"""
        from javax.swing import JDialog, Box
        
        # Crear dialogo modal
        dialog = JDialog()
        dialog.setTitle("Agregar Hallazgo")
        dialog.setModal(True)
        
        # Panel principal
        main_panel = JPanel(BorderLayout())
        
        # Panel de contenido con scroll
        content_panel = JPanel()
        content_panel.setLayout(BoxLayout(content_panel, BoxLayout.Y_AXIS))
        content_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # Plantilla
        vuln_names = sorted(VULN_DB.keys())
        combo_template = JComboBox(["[Personalizado]"] + vuln_names)
        combo_template.setFont(Font("Dialog", Font.PLAIN, 10))
        combo_template.setMaximumSize(Dimension(380, 22))
        
        # Titulo
        txt_title = JTextField()
        txt_title.setFont(Font("Dialog", Font.PLAIN, 10))
        txt_title.setMaximumSize(Dimension(380, 22))
        
        # Severidad
        combo_sev = JComboBox(["Critical", "High", "Medium", "Low", "Info"])
        combo_sev.setFont(Font("Dialog", Font.PLAIN, 10))
        combo_sev.setMaximumSize(Dimension(380, 22))
        
        # Descripcion
        txt_desc = JTextArea(3, 35)
        txt_desc.setFont(Font("Monospaced", Font.PLAIN, 9))
        txt_desc.setLineWrap(True)
        txt_desc.setWrapStyleWord(True)
        
        # Notas
        txt_notes = JTextArea(2, 35)
        txt_notes.setFont(Font("Monospaced", Font.PLAIN, 9))
        txt_notes.setLineWrap(True)
        
        # Auto-completar
        def template_changed(e):
            sel = str(combo_template.getSelectedItem())
            if sel != "[Personalizado]" and sel in VULN_DB:
                v = VULN_DB[sel]
                txt_title.setText(sel)
                txt_desc.setText(v['desc'])
                combo_sev.setSelectedItem(v['severity'])
        
        combo_template.addActionListener(lambda e: template_changed(e))
        
        # Agregar campos
        def add_field(label_text, component):
            lbl = JLabel(label_text)
            lbl.setFont(Font("Dialog", Font.BOLD, 9))
            lbl.setAlignmentX(0.0)
            content_panel.add(lbl)
            component.setAlignmentX(0.0)
            content_panel.add(component)
            content_panel.add(Box.createRigidArea(Dimension(0, 3)))
        
        add_field("Plantilla:", combo_template)
        add_field("Titulo:", txt_title)
        add_field("Severidad:", combo_sev)
        
        # Descripcion con scroll
        content_panel.add(JLabel("Descripcion:"))
        scroll_desc = JScrollPane(txt_desc)
        scroll_desc.setMaximumSize(Dimension(380, 60))
        scroll_desc.setAlignmentX(0.0)
        content_panel.add(scroll_desc)
        content_panel.add(Box.createRigidArea(Dimension(0, 3)))
        
        # Notas con scroll
        content_panel.add(JLabel("Notas:"))
        scroll_notes = JScrollPane(txt_notes)
        scroll_notes.setMaximumSize(Dimension(380, 45))
        scroll_notes.setAlignmentX(0.0)
        content_panel.add(scroll_notes)
        content_panel.add(Box.createRigidArea(Dimension(0, 3)))
        
        # Info
        url_short = url.toString()[:55] + "..." if len(url.toString()) > 55 else url.toString()
        info_label = JLabel("URL: {} | {} | Params: {}".format(url_short, method, len(params)))
        info_label.setFont(Font("Dialog", Font.PLAIN, 8))
        info_label.setForeground(Color(120, 120, 120))
        info_label.setAlignmentX(0.0)
        content_panel.add(info_label)
        
        # Scroll
        scroll_pane = JScrollPane(content_panel)
        scroll_pane.setPreferredSize(Dimension(420, 350))
        scroll_pane.getVerticalScrollBar().setUnitIncrement(16)
        main_panel.add(scroll_pane, BorderLayout.CENTER)
        
        # Botones
        button_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        btn_ok = JButton("Agregar")
        btn_cancel = JButton("Cancelar")
        
        result_holder = [False]
        
        def on_ok(e):
            result_holder[0] = True
            dialog.dispose()
        
        def on_cancel(e):
            dialog.dispose()
        
        btn_ok.addActionListener(on_ok)
        btn_cancel.addActionListener(on_cancel)
        button_panel.add(btn_ok)
        button_panel.add(btn_cancel)
        main_panel.add(button_panel, BorderLayout.SOUTH)
        
        # Mostrar dialogo
        dialog.setContentPane(main_panel)
        dialog.pack()
        dialog.setLocationRelativeTo(None)
        dialog.setVisible(True)
        
        # Procesar
        if result_holder[0]:
            title = txt_title.getText().strip()
            if not title:
                JOptionPane.showMessageDialog(None, "El titulo es obligatorio")
                return
            
            self._add_finding(
                title=title,
                severity=str(combo_sev.getSelectedItem()),
                description=txt_desc.getText(),
                notes=txt_notes.getText(),
                url=url.toString(),
                host=url.getHost(),
                path=url.getPath(),
                method=method,
                headers=list(headers),
                parameters=params,
                request_str=request_str,
                response_str=response_str,
                message=message
            )
            
            self._log_audit("Finding added: " + title, "INFO")
            JOptionPane.showMessageDialog(None, "Hallazgo agregado")
    
    def _add_finding(self, title, severity, description, notes, url, host, path, 
                     method, headers, parameters, request_str, response_str, message):
        """Agrega hallazgo con toda la información capturada"""
        with self._lock:
            # Determinar categoría
            category = 'OTHER'
            for vuln_name, vuln_data in VULN_DB.items():
                if vuln_name in title:
                    category = vuln_data.get('category', 'OTHER')
                    break
            
            finding = {
                'id': self._finding_counter,
                'title': title,
                'severity': severity,
                'description': description,
                'notes': notes,
                'url': url,
                'host': host,
                'path': path,
                'method': method,
                'headers': headers,
                'parameters': parameters,
                'request': request_str,
                'response': response_str,
                'category': category,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'message': message
            }
            
            self._findings.append(finding)
            self._finding_counter += 1
        
        SwingUtilities.invokeLater(lambda: self._refresh_table())
    
    # ========================================================================
    # GESTION DE TABLA
    # ========================================================================
    
    def _refresh_table(self):
        """Refresca la tabla aplicando filtros"""
        self._table_model.setRowCount(0)
        
        search_text = self._txt_search.getText().lower()
        sev_filter = str(self._combo_sev.getSelectedItem())
        cat_filter = str(self._combo_cat.getSelectedItem())
        
        for f in self._findings:
            # Aplicar filtros
            if search_text:
                if search_text not in f['title'].lower() and \
                   search_text not in f['host'].lower() and \
                   search_text not in f['path'].lower():
                    continue
            
            if sev_filter != "Todas" and f['severity'] != sev_filter:
                continue
            
            if cat_filter != "Todas" and f['category'] != cat_filter:
                continue
            
            # Agregar fila
            self._table_model.addRow([
                f['id'],
                f['severity'],
                f['title'],
                f['host'],
                f['path'],
                f['method'],
                OWASP_CATEGORIES.get(f['category'], 'Other'),
                f['timestamp']
            ])
        
        self._update_stats()
    
    def _update_stats(self):
        """Actualiza panel de estadísticas"""
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
            self._audit_log = []
        
        SwingUtilities.invokeLater(lambda: self._refresh_table())
        self._log_audit("New project created", "INFO")
        JOptionPane.showMessageDialog(self._panel, "Nuevo proyecto creado")
    
    def action_save_project(self, event):
        chooser = JFileChooser()
        if chooser.showSaveDialog(self._panel) == JFileChooser.APPROVE_OPTION:
            filepath = str(chooser.getSelectedFile())
            if not filepath.endswith(".json"):
                filepath += ".json"
            
            self._save_to_file(filepath)
            self._log_audit("Project saved: " + filepath, "INFO")
            JOptionPane.showMessageDialog(self._panel, "Proyecto guardado")
    
    def action_load_project(self, event):
        chooser = JFileChooser()
        if chooser.showOpenDialog(self._panel) == JFileChooser.APPROVE_OPTION:
            filepath = str(chooser.getSelectedFile())
            self._load_from_file(filepath)
            self._log_audit("Project loaded: " + filepath, "INFO")
            JOptionPane.showMessageDialog(self._panel, "Proyecto cargado")
    
    def action_edit_finding(self, event):
        row = self._table.getSelectedRow()
        if row == -1:
            JOptionPane.showMessageDialog(self._panel, "Selecciona un hallazgo primero")
            return
        
        idx = self._table.convertRowIndexToModel(row)
        f = self._findings[idx]
        
        panel = JPanel(GridLayout(0, 1, 5, 5))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        txt_title = JTextField(f['title'])
        combo_sev = JComboBox(["Critical", "High", "Medium", "Low", "Info"])
        combo_sev.setSelectedItem(f['severity'])
        txt_desc = JTextArea(f['description'], 5, 40)
        txt_desc.setLineWrap(True)
        txt_notes = JTextArea(f['notes'], 3, 40)
        txt_notes.setLineWrap(True)
        
        panel.add(JLabel("Titulo:"))
        panel.add(txt_title)
        panel.add(JLabel("Severidad:"))
        panel.add(combo_sev)
        panel.add(JLabel("Descripcion:"))
        panel.add(JScrollPane(txt_desc))
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
                f['description'] = txt_desc.getText()
                f['notes'] = txt_notes.getText()
            
            SwingUtilities.invokeLater(lambda: self._refresh_table())
            self._log_audit("Finding edited: ID=" + str(f['id']), "INFO")
            JOptionPane.showMessageDialog(self._panel, "Hallazgo actualizado")
    
    def action_delete_finding(self, event):
        """Eliminar hallazgo de forma segura (ARREGLADO)"""
        row = self._table.getSelectedRow()
        if row == -1:
            JOptionPane.showMessageDialog(self._panel, "Selecciona un hallazgo primero")
            return
        
        result = JOptionPane.showConfirmDialog(
            self._panel, "Eliminar este hallazgo?",
            "Confirmar Eliminacion", JOptionPane.YES_NO_OPTION
        )
        
        if result == JOptionPane.YES_OPTION:
            idx = self._table.convertRowIndexToModel(row)
            
            # FIX: Eliminar de forma segura sin causar threading issues
            with self._lock:
                finding_id = self._findings[idx]['id']
                del self._findings[idx]
            
            # Refrescar tabla en el thread de Swing
            SwingUtilities.invokeLater(lambda: self._refresh_table())
            
            self._log_audit("Finding deleted: ID=" + str(finding_id), "WARN")
            JOptionPane.showMessageDialog(self._panel, "Hallazgo eliminado")
    
    def action_clear_all(self, event):
        """Limpiar todos los hallazgos"""
        if len(self._findings) == 0:
            JOptionPane.showMessageDialog(self._panel, "No hay hallazgos para eliminar")
            return
        
        result = JOptionPane.showConfirmDialog(
            self._panel, "Eliminar TODOS los hallazgos? Esta accion no se puede deshacer.",
            "Confirmar", JOptionPane.YES_NO_OPTION
        )
        
        if result == JOptionPane.YES_OPTION:
            with self._lock:
                count = len(self._findings)
                self._findings = []
            
            SwingUtilities.invokeLater(lambda: self._refresh_table())
            self._log_audit("All findings cleared (" + str(count) + " items)", "WARN")
            JOptionPane.showMessageDialog(self._panel, "Todos los hallazgos eliminados")
    
    def action_view_logs(self, event):
        """Ver logs de auditoría"""
        log_text = "=== LOGS DE AUDITORIA ===\n\n"
        for log in self._audit_log:
            log_text += "[{}] {} - {}\n".format(
                log['timestamp'],
                log['level'],
                log['action']
            )
        
        txt_area = JTextArea(log_text, 20, 60)
        txt_area.setEditable(False)
        txt_area.setFont(Font("Monospaced", Font.PLAIN, 10))
        
        JOptionPane.showMessageDialog(
            self._panel,
            JScrollPane(txt_area),
            "Logs de Auditoria",
            JOptionPane.PLAIN_MESSAGE
        )
    
    # ========================================================================
    # PERSISTENCIA
    # ========================================================================
    
    def _save_to_file(self, filepath):
        """Guarda proyecto en JSON"""
        try:
            export_data = []
            
            for f in self._findings:
                export_data.append({
                    'id': f['id'],
                    'title': f['title'],
                    'severity': f['severity'],
                    'description': f['description'],
                    'notes': f['notes'],
                    'url': f['url'],
                    'host': f['host'],
                    'path': f['path'],
                    'method': f['method'],
                    'headers': f['headers'],
                    'parameters': f['parameters'],
                    'request': base64.b64encode(f['request'].encode('utf-8')).decode('ascii'),
                    'response': base64.b64encode(f['response'].encode('utf-8')).decode('ascii'),
                    'category': f['category'],
                    'timestamp': f['timestamp']
                })
            
            project = {
                'version': '8.0',
                'timestamp': datetime.now().isoformat(),
                'finding_counter': self._finding_counter,
                'findings': export_data,
                'audit_log': self._audit_log
            }
            
            with codecs.open(filepath, 'w', 'utf-8') as file:
                json.dump(project, file, indent=2, ensure_ascii=False)
                
        except Exception as e:
            print("Error guardando: " + str(e))
            JOptionPane.showMessageDialog(self._panel, "❌ Error: " + str(e))
    
    def _load_from_file(self, filepath):
        """Carga proyecto desde JSON"""
        try:
            with codecs.open(filepath, 'r', 'utf-8') as file:
                project = json.load(file)
            
            with self._lock:
                self._findings = []
                self._finding_counter = project.get('finding_counter', 1)
                self._audit_log = project.get('audit_log', [])
                
                for item in project.get('findings', []):
                    finding = {
                        'id': item['id'],
                        'title': item['title'],
                        'severity': item['severity'],
                        'description': item['description'],
                        'notes': item['notes'],
                        'url': item['url'],
                        'host': item['host'],
                        'path': item['path'],
                        'method': item['method'],
                        'headers': item['headers'],
                        'parameters': item['parameters'],
                        'request': base64.b64decode(item['request']).decode('utf-8'),
                        'response': base64.b64decode(item['response']).decode('utf-8'),
                        'category': item.get('category', 'OTHER'),
                        'timestamp': item['timestamp'],
                        'message': None
                    }
                    self._findings.append(finding)
            
            SwingUtilities.invokeLater(lambda: self._refresh_table())
            
        except Exception as e:
            print("Error cargando: " + str(e))
            JOptionPane.showMessageDialog(self._panel, "❌ Error: " + str(e))
    
    # ========================================================================
    # EXPORTACION
    # ========================================================================
    
    def action_export_json(self, event):
        chooser = JFileChooser()
        if chooser.showSaveDialog(self._panel) == JFileChooser.APPROVE_OPTION:
            filepath = str(chooser.getSelectedFile())
            if not filepath.endswith(".json"):
                filepath += ".json"
            
            self._save_to_file(filepath)
            self._log_audit("Exported to JSON: " + filepath, "INFO")
            JOptionPane.showMessageDialog(self._panel, "JSON exportado")
    
    def action_export_faraday(self, event):
        chooser = JFileChooser()
        if chooser.showSaveDialog(self._panel) == JFileChooser.APPROVE_OPTION:
            filepath = str(chooser.getSelectedFile())
            if not filepath.endswith(".json"):
                filepath += ".json"
            
            self._export_faraday_format(filepath)
            self._log_audit("Exported to Faraday: " + filepath, "INFO")
            JOptionPane.showMessageDialog(self._panel, "Faraday exportado")
    
    def _export_faraday_format(self, filepath):
        """Exporta en formato Faraday"""
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
                'desc': f['description'],
                'severity': severity_map.get(f['severity'], 'informational'),
                'resolution': f['notes'],
                'data': '',
                'website': '',
                'path': f['path'],
                'request': f['request'][:1000] if f['request'] else '',
                'response': f['response'][:1000] if f['response'] else '',
                'method': f['method'],
                'params': str(f['parameters'])[:500] if f['parameters'] else '',
                'category': OWASP_CATEGORIES.get(f['category'], 'Other'),
                'status': 'opened',
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
        
        with codecs.open(filepath, 'w', 'utf-8') as file:
            json.dump(data, file, indent=2, ensure_ascii=False)
    
    def action_generate_report(self, event):
        """Genera reporte HTML profesional"""
        panel = JPanel(GridLayout(0, 1, 5, 5))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        txt_project = JTextField("Security Assessment")
        txt_client = JTextField("Client Name")
        txt_auditor = JTextField("Security Team")
        txt_summary = JTextArea(5, 40)
        txt_summary.setText("Durante la evaluacion se identificaron vulnerabilidades de seguridad.")
        txt_summary.setLineWrap(True)
        
        panel.add(JLabel("Proyecto:"))
        panel.add(txt_project)
        panel.add(JLabel("Cliente:"))
        panel.add(txt_client)
        panel.add(JLabel("Auditor:"))
        panel.add(txt_auditor)
        panel.add(JLabel("Resumen:"))
        panel.add(JScrollPane(txt_summary))
        
        result = JOptionPane.showConfirmDialog(
            self._panel, panel, "Generar Reporte HTML",
            JOptionPane.OK_CANCEL_OPTION
        )
        
        if result == JOptionPane.OK_OPTION:
            chooser = JFileChooser()
            if chooser.showSaveDialog(self._panel) == JFileChooser.APPROVE_OPTION:
                filepath = str(chooser.getSelectedFile())
                if not filepath.endswith(".html"):
                    filepath += ".html"
                
                self._generate_html(
                    filepath,
                    txt_project.getText(),
                    txt_client.getText(),
                    txt_auditor.getText(),
                    txt_summary.getText()
                )
                
                self._log_audit("HTML report generated: " + filepath, "INFO")
                JOptionPane.showMessageDialog(self._panel, "Reporte HTML generado")
    
    def _escape_html(self, text):
        if not text:
            return ""
        try:
            if isinstance(text, str):
                text = text.decode('utf-8', 'ignore')
        except:
            pass
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    
    def _generate_html(self, filepath, project, client, auditor, summary):
        """Genera reporte HTML moderno"""
        counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for f in self._findings:
            if f['severity'] in counts:
                counts[f['severity']] += 1
        
        # CSS Moderno
        css = """
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: 'Segoe UI', Arial, sans-serif; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: #2c3e50; 
                line-height: 1.6;
            }
            .container { 
                max-width: 1200px; 
                margin: 0 auto; 
                background: white;
                box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            }
            .header { 
                background: linear-gradient(135deg, #1a237e 0%, #283593 100%); 
                color: white; 
                padding: 3rem 2rem; 
                text-align: center;
                border-bottom: 5px solid #ffd700;
            }
            .header h1 { font-size: 2.5rem; margin-bottom: 1rem; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
            .header p { font-size: 1.1rem; opacity: 0.95; }
            
            .content { padding: 2rem; }
            
            .metrics { 
                display: grid; 
                grid-template-columns: repeat(5, 1fr); 
                gap: 1rem; 
                margin: 2rem 0;
            }
            .metric-card { 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 1.5rem; 
                border-radius: 12px; 
                text-align: center;
                box-shadow: 0 4px 15px rgba(0,0,0,0.1);
                transition: transform 0.3s;
            }
            .metric-card:hover { transform: translateY(-5px); }
            .metric-card h3 { font-size: 2.5rem; margin-bottom: 0.5rem; }
            .metric-card p { font-size: 0.9rem; opacity: 0.9; text-transform: uppercase; }
            
            .critical-card { background: linear-gradient(135deg, #c62828 0%, #e53935 100%); }
            .high-card { background: linear-gradient(135deg, #f57c00 0%, #ff9800 100%); }
            .medium-card { background: linear-gradient(135deg, #fbc02d 0%, #fdd835 100%); }
            .low-card { background: linear-gradient(135deg, #1976d2 0%, #2196f3 100%); }
            .info-card { background: linear-gradient(135deg, #388e3c 0%, #4caf50 100%); }
            
            .summary-box {
                background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
                border-left: 5px solid #1976d2;
                padding: 1.5rem;
                margin: 2rem 0;
                border-radius: 8px;
            }
            .summary-box h2 { color: #1976d2; margin-bottom: 1rem; }
            
            .finding { 
                background: white;
                margin: 1.5rem 0; 
                border-radius: 12px; 
                overflow: hidden;
                box-shadow: 0 4px 15px rgba(0,0,0,0.1);
                border-left: 5px solid #ccc;
                transition: transform 0.3s;
            }
            .finding:hover { transform: translateX(5px); }
            
            .finding-critical { border-left-color: #c62828; }
            .finding-high { border-left-color: #f57c00; }
            .finding-medium { border-left-color: #fbc02d; }
            .finding-low { border-left-color: #1976d2; }
            .finding-info { border-left-color: #388e3c; }
            
            .finding-header {
                padding: 1.5rem;
                background: linear-gradient(to right, #f8f9fa, #ffffff);
                border-bottom: 2px solid #e9ecef;
            }
            .finding-title { 
                font-size: 1.4rem; 
                font-weight: bold; 
                margin-bottom: 0.5rem;
            }
            .finding-meta {
                color: #6c757d;
                font-size: 0.9rem;
            }
            .finding-body {
                padding: 1.5rem;
            }
            
            .code-block { 
                background: #1e1e1e; 
                color: #d4d4d4; 
                padding: 1rem; 
                border-radius: 6px; 
                overflow-x: auto; 
                font-family: 'Courier New', monospace; 
                font-size: 0.85rem;
                margin: 1rem 0;
            }
            
            .badge {
                display: inline-block;
                padding: 0.3rem 0.8rem;
                border-radius: 20px;
                font-size: 0.85rem;
                font-weight: bold;
                margin-right: 0.5rem;
            }
            .badge-critical { background: #c62828; color: white; }
            .badge-high { background: #f57c00; color: white; }
            .badge-medium { background: #fbc02d; color: #333; }
            .badge-low { background: #1976d2; color: white; }
            .badge-info { background: #388e3c; color: white; }
            
            @media print {
                body { background: white; }
                .container { box-shadow: none; }
                .finding { page-break-inside: avoid; }
            }
        </style>
        """
        
        # HTML
        html = u"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{project} - Security Assessment Report</title>
    {css}
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ {project}</h1>
            <p><strong>Cliente:</strong> {client} | <strong>Auditor:</strong> {auditor}</p>
            <p><strong>Fecha:</strong> {date}</p>
        </div>
        
        <div class="content">
            <div class="metrics">
                <div class="metric-card critical-card">
                    <h3>{critical}</h3>
                    <p>Critical</p>
                </div>
                <div class="metric-card high-card">
                    <h3>{high}</h3>
                    <p>High</p>
                </div>
                <div class="metric-card medium-card">
                    <h3>{medium}</h3>
                    <p>Medium</p>
                </div>
                <div class="metric-card low-card">
                    <h3>{low}</h3>
                    <p>Low</p>
                </div>
                <div class="metric-card info-card">
                    <h3>{info}</h3>
                    <p>Info</p>
                </div>
            </div>
            
            <div class="summary-box">
                <h2>📋 Resumen Ejecutivo</h2>
                <p>{summary}</p>
            </div>
            
            <h2 style="margin: 2rem 0 1rem 0; color: #1a237e;">🔍 Hallazgos Detallados</h2>
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
        
        # Hallazgos ordenados por severidad
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        sorted_findings = sorted(self._findings, key=lambda f: severity_order.get(f['severity'], 99))
        
        for f in sorted_findings:
            # Truncar request/response si son muy largos
            req = f['request'][:5000] if f['request'] else "No disponible"
            res = f['response'][:8000] if f['response'] else "No disponible"
            
            if len(f['request']) > 5000:
                req += "\n\n... [TRUNCADO - Request muy largo]"
            if len(f['response']) > 8000:
                res += "\n\n... [TRUNCADO - Response muy largo]"
            
            # Parámetros
            params_html = ""
            if f['parameters']:
                params_html = "<strong>Parametros:</strong><ul>"
                for param in f['parameters'][:10]:  # Máximo 10 parámetros
                    params_html += "<li><code>{}</code> = <code>{}</code> ({})</li>".format(
                        self._escape_html(str(param.get('name', ''))),
                        self._escape_html(str(param.get('value', '')))[:50],
                        param.get('type', 'Unknown')
                    )
                params_html += "</ul>"
            
            html += u"""
            <div class="finding finding-{sev_lower}">
                <div class="finding-header">
                    <div class="finding-title">
                        {title}
                        <span class="badge badge-{sev_lower}">{severity}</span>
                    </div>
                    <div class="finding-meta">
                        <strong>🌐 URL:</strong> {url}<br>
                        <strong>🔧 Método:</strong> {method} | 
                        <strong>🏷️ Categoría:</strong> {category} | 
                        <strong>🕒 Timestamp:</strong> {timestamp}
                    </div>
                </div>
                <div class="finding-body">
                    <p><strong>📄 Descripción:</strong></p>
                    <p>{desc}</p>
                    
                    {params}
                    
                    <p><strong>📝 Notas:</strong></p>
                    <p>{notes}</p>
                    
                    <p><strong>📨 Request:</strong></p>
                    <div class="code-block">{req}</div>
                    
                    <p><strong>📬 Response:</strong></p>
                    <div class="code-block">{res}</div>
                </div>
            </div>
""".format(
                sev_lower=f['severity'].lower(),
                title=self._escape_html(f['title']),
                severity=f['severity'],
                url=self._escape_html(f['url']),
                method=f['method'],
                category=OWASP_CATEGORIES.get(f['category'], 'Other'),
                timestamp=f['timestamp'],
                desc=self._escape_html(f['description']),
                params=params_html,
                notes=self._escape_html(f['notes']) if f['notes'] else "Sin notas adicionales",
                req=self._escape_html(req),
                res=self._escape_html(res)
            )
        
        html += """
        </div>
    </div>
</body>
</html>"""
        
        with codecs.open(filepath, 'w', 'utf-8') as file:
            file.write(html)
    
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
            idx = self._table.convertRowIndexToModel(row)
            f = self._findings[idx]
            if f.get('message'):
                return f['message'].getHttpService()
        return None
    
    def getRequest(self):
        row = self._table.getSelectedRow()
        if row != -1:
            idx = self._table.convertRowIndexToModel(row)
            f = self._findings[idx]
            if f.get('message'):
                return f['message'].getRequest()
        return None
    
    def getResponse(self):
        row = self._table.getSelectedRow()
        if row != -1:
            idx = self._table.convertRowIndexToModel(row)
            f = self._findings[idx]
            if f.get('message'):
                return f['message'].getResponse()
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
        
        idx = self._ext._table.convertRowIndexToModel(row)
        f = self._ext._findings[idx]
        
        # Detalles
        detail = u"""╔══════════════════════════════════════════════════════════════╗
║                    DETALLES DEL HALLAZGO                     ║
╚══════════════════════════════════════════════════════════════╝

ID: {id}
Título: {title}
Severidad: {severity}
Categoría OWASP: {category}

URL: {url}
Host: {host}
Path: {path}
Método: {method}

Timestamp: {timestamp}

─────────────────────────────────────────────────────────────
DESCRIPCIÓN:
{desc}

─────────────────────────────────────────────────────────────
NOTAS:
{notes}

─────────────────────────────────────────────────────────────
PARÁMETROS CAPTURADOS: {param_count}
{params}
""".format(
            id=f['id'],
            title=f['title'],
            severity=f['severity'],
            category=OWASP_CATEGORIES.get(f['category'], 'Other'),
            url=f['url'],
            host=f['host'],
            path=f['path'],
            method=f['method'],
            timestamp=f['timestamp'],
            desc=f['description'],
            notes=f['notes'] if f['notes'] else "Sin notas adicionales",
            param_count=len(f['parameters']),
            params="\n".join([
                "  • {} = {} ({})".format(
                    p.get('name', ''),
                    str(p.get('value', ''))[:50],
                    p.get('type', 'Unknown')
                ) for p in f['parameters'][:10]
            ]) if f['parameters'] else "  No hay parámetros"
        )
        
        self._ext._txt_detail.setText(detail)
        
        # Viewers
        msg = f.get('message')
        if msg:
            self._ext._req_viewer.setMessage(msg.getRequest(), True)
            self._ext._res_viewer.setMessage(msg.getResponse(), False)
        else:
            # Si no hay mensaje, mostrar texto
            self._ext._req_viewer.setMessage(
                self._ext._helpers.stringToBytes(f['request']),
                True
            )
            self._ext._res_viewer.setMessage(
                self._ext._helpers.stringToBytes(f['response']),
                False
            )

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
