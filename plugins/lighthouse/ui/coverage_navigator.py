import logging
import logging
import weakref
from lighthouse.util.qt import *
from lighthouse.util.disassembler import disassembler
from lighthouse.util.python import *
from lighthouse.util.misc import mainthread
from lighthouse.coverage import BADADDR

logger = logging.getLogger("Lighthouse.UI.Navigator")

#------------------------------------------------------------------------------
# Logging Helpers
#------------------------------------------------------------------------------

def log_debug(msg):
    """Log debug message."""
    logger.debug(msg)
    print("[Debug] %s" % msg)

def log_info(msg):
    """Log info message."""
    logger.info(msg)
    print("[Info] %s" % msg)

def log_print(msg):
    """Print message directly to console for debugging."""
    print("[Navigator] %s" % msg)

#------------------------------------------------------------------------------
# BB Coverage Navigator
#------------------------------------------------------------------------------

class CoverageTableView(QtWidgets.QTableView):
    def __init__(self, controller, model, parent=None):
        super(CoverageTableView, self).__init__(parent)
        log_print("CoverageTableView: Initializing...")
        self.setObjectName(self.__class__.__name__)
        self._controller = controller
        self._model = model
        self.setModel(self._model)
        log_print("CoverageTableView: model set, view.model()=%s" % self.model())
        self._ui_init()
        self.refresh_theme()
        log_print("CoverageTableView: Initialization complete")

    @disassembler.execute_ui
    def refresh_theme(self):
        palette = self._model.lctx.palette
        self.setStyleSheet(
            "QTableView {"
            "  gridline-color: %s;" % palette.table_grid.name() +
            "  background-color: %s;" % palette.table_background.name() +
            "  color: %s;" % palette.table_text.name() +
            "  outline: none; "
            "} " +
            "QHeaderView::section { "
            "  padding: 1ex;"  \
            "  margin: 0;"  \
            "} " +
            "QTableView::item:selected {"
            "  color: white; " \
            "  background-color: %s;" % palette.table_selection.name() +
            "}"
        )

    def keyPressEvent(self, event):
        if event.key() == QtCore.Qt.Key_J:
            event = remap_key_event(event, QtCore.Qt.Key_Down)
        elif event.key() == QtCore.Qt.Key_K:
            event = remap_key_event(event, QtCore.Qt.Key_Up)
        elif event.key() == QtCore.Qt.Key_H:
            event = remap_key_event(event, QtCore.Qt.Key_Left)
        elif event.key() == QtCore.Qt.Key_L:
            event = remap_key_event(event, QtCore.Qt.Key_Right)

        super(CoverageTableView, self).keyPressEvent(event)
        self.repaint()
        flush_qt_events()

    def _ui_init(self):
        self.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.setHorizontalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
        self.setMinimumHeight(100)  # Ensure minimum height
        self.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding,
            QtWidgets.QSizePolicy.Expanding
        )

        title_font = self._model.headerData(0, QtCore.Qt.Horizontal, QtCore.Qt.FontRole)
        title_fm = QtGui.QFontMetricsF(title_font)
        entry_font = self._model.data(0, QtCore.Qt.FontRole)
        entry_fm = QtGui.QFontMetricsF(entry_font)

        for i in xrange(self._model.columnCount()):
            title_rect = self._model.headerData(i, QtCore.Qt.Horizontal, QtCore.Qt.SizeHintRole)
            entry_text = self._model.SAMPLE_CONTENTS[i]
            entry_rect = entry_fm.boundingRect(entry_text)
            column_width = int(max(title_rect.width(), entry_rect.width()*1.2))
            self.setColumnWidth(i, column_width)

        self.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        vh = self.verticalHeader()
        hh = self.horizontalHeader()
        # vh.hide()  # Temporarily show vertical header for debugging
        hh.setStretchLastSection(True)
        hh.setHighlightSections(False)
        self.setSortingEnabled(False)
        # vh.setSectionResizeMode(QtWidgets.QHeaderView.Fixed)  # Try without fixed mode
        spacing = entry_fm.height() - entry_fm.xHeight()
        tweak = (17*get_dpi_scale() - spacing)/get_dpi_scale()
        row_height = int(entry_fm.height()+tweak)
        log_print("_ui_init: row_height=%d, entry_fm.height()=%f, tweak=%f" % (row_height, entry_fm.height(), tweak))
        vh.setDefaultSectionSize(row_height)
        
        # Debug: check actual row height after setting
        log_print("_ui_init: vh.defaultSectionSize()=%d, vh.count()=%d" % (vh.defaultSectionSize(), vh.count()))

        self.doubleClicked.connect(self._ui_entry_double_click)
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._ui_table_ctx_menu_handler)

    def _ui_entry_double_click(self, index):
        log_print("_ui_entry_double_click: index.row()=%d, index.column()=%d" % (index.row(), index.column()))
        self._controller.navigate_to_bb(index.row())

    def _ui_table_ctx_menu_handler(self, position):
        selected_row_indexes = self.selectionModel().selectedRows()
        if len(selected_row_indexes) == 0:
            return

        ctx_menu = QtWidgets.QMenu()
        _action_navigate = QtWidgets.QAction("Navigate to Address", None)
        ctx_menu.addAction(_action_navigate)

        if USING_PYSIDE6:
            exec_func = getattr(ctx_menu, "exec")
        else:
            exec_func = getattr(ctx_menu, "exec_")

        action = exec_func(self.viewport().mapToGlobal(position))
        if action == _action_navigate:
            row = selected_row_indexes[0].row()
            self._controller.navigate_to_bb(row)

class CoverageTableController(object):
    def __init__(self, lctx, model):
        self.lctx = lctx
        self._model = model
        log_debug("CoverageTableController initialized")

    def navigate_to_bb(self, row):
        """
        Navigate to the basic block depicted by the given row.
        """
        log_print("navigate_to_bb called with row=%d" % row)
        log_print("  _model.row2bb keys: %s" % list(self._model.row2bb.keys())[:10])
        
        bb_address = self._model.row2bb.get(row, BADADDR)
        log_print("  bb_address=0x%X" % bb_address)
        
        if bb_address == BADADDR:
            log_print("  Invalid address for row %d" % row)
            return

        # get the function containing this basic block
        log_print("  lctx=%s, lctx.director=%s" % (self.lctx, self.lctx.director))
        funcs = self.lctx.director.metadata.get_functions_containing(bb_address)
        log_print("  funcs=%s" % funcs)
        if funcs:
            function_address = funcs[0].address
        else:
            function_address = bb_address

        log_print("  Navigating to BB at 0x%X (func: 0x%X, row #%d)" % (bb_address, function_address, row))

        # navigate to the function + basic block
        disassembler[self.lctx].navigate_to_function(function_address, bb_address)
        log_print("  navigate_to_function completed")

class CoverageTableModel(QtCore.QAbstractTableModel):
    BB_INDEX = 0
    FUNC_NAME = 1
    BB_OFFSET = 2
    BB_ADDRESS = 3

    COLUMN_HEADERS = {
        BB_INDEX: "#",
        FUNC_NAME: "Function",
        BB_OFFSET: "BB Offset",
        BB_ADDRESS: "Address",
    }

    COLUMN_TOOLTIPS = {
        BB_INDEX: "BB Index in coverage",
        FUNC_NAME: "Function Name",
        BB_OFFSET: "Basic Block Offset",
        BB_ADDRESS: "BB Address (absolute)",
    }

    SAMPLE_CONTENTS = [
        " 1 ",
        " sub_140001B20 ",
        " 0x1A06 ",
        " 0x140001A06 ",
    ]

    def __init__(self, lctx, parent=None):
        super(CoverageTableModel, self).__init__(parent)
        log_print("CoverageTableModel: Initializing...")
        self.lctx = lctx
        self._director = lctx.director if lctx and lctx.director else None
        log_print("CoverageTableModel: lctx=%s, lctx.director=%s" % (lctx, getattr(lctx, 'director', 'N/A')))
        self.row2bb = {}
        self.row2offset = {}
        self._row_count = 0
        self._bb_coverage = []

        self._default_alignment = QtCore.Qt.AlignCenter
        self._column_alignment = [self._default_alignment for x in self.COLUMN_HEADERS]
        self.set_column_alignment(self.FUNC_NAME, QtCore.Qt.AlignVCenter)

        self._entry_font = MonospaceFont()
        if not USING_PYSIDE6:
            self._entry_font.setStyleStrategy(QtGui.QFont.ForceIntegerMetrics)
        self._entry_font.setPointSizeF(normalize_to_dpi(10))
        self._title_font = QtGui.QFont()
        self._title_font.setPointSizeF(normalize_to_dpi(10))

        if self._director:
            self._director.coverage_switched(self._internal_refresh)
            self._director.coverage_modified(self._internal_refresh)
            log_print("CoverageTableModel: Registered for coverage events")
        else:
            log_print("CoverageTableModel: No director available during init")

        log_print("CoverageTableModel: Initialization complete")

    def refresh_theme(self):
        self._data_changed()

    def flags(self, index):
        return QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable

    def rowCount(self, index=QtCore.QModelIndex()):
        return self._row_count

    def columnCount(self, index=QtCore.QModelIndex()):
        return len(self.COLUMN_HEADERS)

    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole):
        """
        Define the properties of the table rows & columns.
        """
        if orientation == QtCore.Qt.Horizontal:

            # the title of the header columns has been requested
            if role == QtCore.Qt.DisplayRole:
                return self.COLUMN_HEADERS.get(section, None)

            # the text alignment of the header has been requested
            elif role == QtCore.Qt.TextAlignmentRole:
                return self._column_alignment[section]

            # tooltip request
            elif role == QtCore.Qt.ToolTipRole:
                return self.COLUMN_TOOLTIPS.get(section, None)

            # font format request
            elif role == QtCore.Qt.FontRole:
                return self._title_font

        # size hint request (only for horizontal headers)
        if role == QtCore.Qt.SizeHintRole and orientation == QtCore.Qt.Horizontal:
            title_fm = QtGui.QFontMetricsF(self._title_font)
            title_rect = title_fm.boundingRect(self.COLUMN_HEADERS.get(section, ""))
            padded = QtCore.QSize(int(title_rect.width()*1.45), int(title_rect.height()*1.75))
            return padded

        # unhandled header request
        return None

    def data(self, index, role=QtCore.Qt.DisplayRole):
        # Handle case where index is not a QModelIndex (e.g., integer passed for font query)
        if not hasattr(index, 'row'):
            if role == QtCore.Qt.FontRole:
                return self._entry_font
            return None

        row = index.row()
        column = index.column()
        
        if role == QtCore.Qt.DisplayRole:
            bb_address = self.row2bb.get(row, BADADDR)
            offset = self.row2offset.get(row, 0)

            if bb_address == BADADDR:
                if column == self.FUNC_NAME:
                    return "No Coverage"
                return "N/A"

            if not self._director:
                if column == self.FUNC_NAME:
                    return "Loading..."
                return "N/A"

            funcs = self._director.metadata.get_functions_containing(bb_address)
            func_metadata = funcs[0] if funcs else None

            if column == self.BB_INDEX:
                return "%u" % row
            elif column == self.FUNC_NAME:
                if func_metadata:
                    return func_metadata.name
                return "Unknown"
            elif column == self.BB_OFFSET:
                return "0x%X" % offset
            elif column == self.BB_ADDRESS:
                return "0x%X" % bb_address

        elif role == QtCore.Qt.BackgroundRole:
            bb_address = self.row2bb.get(index.row(), BADADDR)
            if bb_address == BADADDR or not self._director:
                return None

            node_coverage = self._director.coverage.nodes.get(bb_address, None)
            if node_coverage:
                return self.lctx.palette.table_coverage_good
            return None

        elif role == QtCore.Qt.FontRole:
            return self._entry_font

        elif role == QtCore.Qt.TextAlignmentRole:
            return self._column_alignment[index.column()]

        return None

    def set_column_alignment(self, column, alignment):
        self._column_alignment[column] = alignment
        self._alignment_changed(column)

    def refresh(self):
        self._internal_refresh()

    @disassembler.execute_ui
    def _internal_refresh(self):
        log_print("_internal_refresh: Starting...")
        log_print("_internal_refresh: self=%s, row_count before=%d" % (self, self._row_count))
        self._refresh_data()
        log_print("_internal_refresh: emitting layoutChanged...")
        self.layoutChanged.emit()
        log_print("_internal_refresh: Complete, row_count=%d, row2bb len=%d" % (self._row_count, len(self.row2bb)))

    def _refresh_data(self):
        log_print("_refresh_data: Starting refresh...")
        row = 0
        self.row2bb = {}
        self.row2offset = {}
        self._row_count = 0
        self._bb_coverage = []

        if not self._director:
            log_print("_refresh_data: No director available, aborting")
            return

        coverage = self._director.coverage
        if not coverage:
            log_print("_refresh_data: No coverage data available")
            return

        metadata = self._director.metadata
        imagebase = metadata.imagebase

        log_print("_refresh_data: imagebase=0x%X, coverage nodes=%d" % (imagebase, len(coverage.nodes)))

        self._bb_coverage = list(coverage.nodes_in_order)
        for bb_address in self._bb_coverage:
            self.row2bb[row] = bb_address
            self.row2offset[row] = bb_address - imagebase
            row += 1

        self._row_count = len(self.row2bb)
        log_print("_refresh_data: Loaded %d basic blocks" % self._row_count)

    @disassembler.execute_ui
    def _data_changed(self):
        self.dataChanged.emit(QtCore.QModelIndex(), QtCore.QModelIndex())

    @disassembler.execute_ui
    def _alignment_changed(self, column):
        self.dataChanged.emit(QtCore.QModelIndex(), QtCore.QModelIndex())
        self.headerDataChanged.emit(QtCore.Qt.Horizontal, column, column)

#------------------------------------------------------------------------------
# Fuzz Target Dialog
#------------------------------------------------------------------------------

class FuzzTargetDialog(QtWidgets.QDialog):
    """
    A dialog that shows all covered functions ranked by their trace span.
    Double-clicking a row navigates to that function's first BB in the trace.
    """

    def __init__(self, ranked, total_rows, table_view, table_model, table_controller, parent=None):
        super(FuzzTargetDialog, self).__init__(parent)
        self._ranked = ranked
        self._total_rows = total_rows
        self._table_view = table_view
        self._table_model = table_model
        self._table_controller = table_controller
        self._ui_init()

    def _ui_init(self):
        self.setWindowTitle("Fuzz Targets (ranked by trace span)")
        self.setWindowFlags(self.windowFlags() & ~QtCore.Qt.WindowContextHelpButtonHint)
        self.setMinimumSize(650, 400)

        self._font = MonospaceFont()
        self._font.setPointSizeF(normalize_to_dpi(10))

        # table
        self._table = QtWidgets.QTableWidget()
        self._table.setColumnCount(4)
        self._table.setHorizontalHeaderLabels(["#", "Function", "Span (BBs)", "Span %"])
        self._table.verticalHeader().setVisible(False)
        self._table.setHorizontalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
        self._table.horizontalHeader().setFont(self._font)
        self._table.setFont(self._font)
        self._table.setWordWrap(False)
        self._table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self._table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self._table.horizontalHeader().setHighlightSections(False)
        self._table.horizontalHeader().setSectionResizeMode(1, QtWidgets.QHeaderView.Stretch)
        self._table.setColumnWidth(0, 50)
        self._table.setColumnWidth(2, 100)
        self._table.setColumnWidth(3, 90)

        self._populate_table()

        self._table.cellDoubleClicked.connect(self._on_double_click)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self._table)
        self.setLayout(layout)

    def _populate_table(self):
        self._table.setRowCount(len(self._ranked))
        for i, (func_name, func_address, span, span_percent, first_row) in enumerate(self._ranked):
            item_rank = QtWidgets.QTableWidgetItem("%d" % (i + 1))
            item_rank.setTextAlignment(QtCore.Qt.AlignCenter)

            item_name = QtWidgets.QTableWidgetItem(func_name)

            item_span = QtWidgets.QTableWidgetItem("%d" % span)
            item_span.setTextAlignment(QtCore.Qt.AlignCenter)

            item_pct = QtWidgets.QTableWidgetItem("%.2f%%" % span_percent)
            item_pct.setTextAlignment(QtCore.Qt.AlignCenter)

            self._table.setItem(i, 0, item_rank)
            self._table.setItem(i, 1, item_name)
            self._table.setItem(i, 2, item_span)
            self._table.setItem(i, 3, item_pct)

    def _on_double_click(self, row, column):
        if row < 0 or row >= len(self._ranked):
            return

        func_name, func_address, span, span_percent, first_row = self._ranked[row]
        log_print("Fuzz target selected: %s (span %d, %.2f%%)" % (func_name, span, span_percent))

        self._table_view.selectRow(first_row)
        self._table_view.scrollTo(self._table_model.index(first_row, 0))
        self._table_controller.navigate_to_bb(first_row)

#------------------------------------------------------------------------------
# BB Coverage Navigator Widget
#------------------------------------------------------------------------------

class CoverageNavigator(object):
    def __init__(self, lctx, widget):
        log_print("CoverageNavigator: Initializing...")
        self.lctx = lctx
        self.widget = widget

        # Store reference in context for visibility checks
        self.lctx.coverage_navigator = self

        # Event filter for widget lifecycle
        self._events = NavigatorEventProxy(self)
        self.widget.installEventFilter(self._events)

        self._ui_init()
        self.refresh()

        self._director = self.lctx.director if lctx and lctx.director else None
        if self._director:
            self._director.refreshed(self.refresh)
            log_print("CoverageNavigator: Registered for director refresh events")
        else:
            log_print("CoverageNavigator: No director available")

        log_print("CoverageNavigator: Initialization complete")

    @property
    def name(self):
        if not self.widget:
            return "BB Coverage Navigator"
        return self.widget.name

    @property
    def visible(self):
        if not self.widget:
            return False
        return self.widget.visible

    def terminate(self):
        log_debug("CoverageNavigator: Terminating...")
        self._table_controller = None
        self._table_model = None
        self._table_view = None
        self._toolbar = None
        self._status_label = None
        self.widget = None

    def _ui_init(self):
        log_debug("CoverageNavigator: Initializing UI...")
        self._ui_init_table()
        self._ui_init_toolbar()
        self._ui_layout()

    def _ui_init_table(self):
        self._table_model = CoverageTableModel(self.lctx, self.widget)
        self._table_controller = CoverageTableController(self.lctx, self._table_model)
        self._table_view = CoverageTableView(self._table_controller, self._table_model, self.widget)
        self._setup_hotkeys()

    def _ui_init_toolbar(self):
        """Initialize the navigation toolbar."""
        log_debug("CoverageNavigator: Initializing toolbar...")

        # Create toolbar
        self._toolbar = QtWidgets.QToolBar()
        self._toolbar.setStyleSheet('QToolBar{padding:0;margin:0;}')

        # Previous button
        self._prev_button = QtWidgets.QToolButton()
        self._prev_button.setText("<")
        self._prev_button.setToolTip("Previous basic block (Ctrl+Left)")
        self._prev_button.clicked.connect(self._navigate_prev)

        # Next button
        self._next_button = QtWidgets.QToolButton()
        self._next_button.setText(">")
        self._next_button.setToolTip("Next basic block (Ctrl+Right)")
        self._next_button.clicked.connect(self._navigate_next)

        # Prev in function button
        self._prev_in_function_button = QtWidgets.QToolButton()
        self._prev_in_function_button.setText("<<")
        self._prev_in_function_button.setToolTip("Previous basic block in current function (Ctrl+Shift+Left)")
        self._prev_in_function_button.clicked.connect(self._navigate_prev_in_function)

        # Next in function button
        self._next_in_function_button = QtWidgets.QToolButton()
        self._next_in_function_button.setText(">>")
        self._next_in_function_button.setToolTip("Next basic block in current function (Ctrl+Shift+Right)")
        self._next_in_function_button.clicked.connect(self._navigate_next_in_function)

        # Sync button
        self._sync_button = QtWidgets.QToolButton()
        self._sync_button.setIcon(get_qt_icon("SP_BrowserReload"))
        self._sync_button.setToolTip("Sync with current IDA location (S)")
        self._sync_button.clicked.connect(self._sync_with_ida)

        # Best fuzzing target button
        self._fuzz_target_button = QtWidgets.QToolButton()
        self._fuzz_target_button.setText("Fuzz")
        self._fuzz_target_button.setToolTip("Jump to best fuzzing target function (F)")
        self._fuzz_target_button.clicked.connect(self._navigate_best_fuzz_target)

        # Refresh button
        self._refresh_button = QtWidgets.QToolButton()
        self._refresh_button.setIcon(get_qt_icon("SP_BrowserReload"))
        self._refresh_button.setToolTip("Refresh coverage data")
        self._refresh_button.clicked.connect(self._on_refresh_clicked)

        # Status label
        self._status_label = QtWidgets.QLabel("0 basic blocks")
        self._status_label.setStyleSheet("QLabel { padding: 0 8px; }")

        # Spacer to push status label to the right
        spacer = QtWidgets.QWidget()
        spacer.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)

        # Add widgets to toolbar
        self._toolbar.addWidget(self._prev_button)
        self._toolbar.addWidget(self._next_button)
        self._toolbar.addWidget(self._prev_in_function_button)
        self._toolbar.addWidget(self._next_in_function_button)
        self._toolbar.addWidget(self._sync_button)
        self._toolbar.addWidget(self._fuzz_target_button)
        self._toolbar.addSeparator()
        self._toolbar.addWidget(self._refresh_button)
        self._toolbar.addWidget(spacer)
        self._toolbar.addWidget(self._status_label)

    def _setup_hotkeys(self):
        """Setup keyboard hotkeys for navigation."""
        # Previous/Next BB navigation (Ctrl/Cmd + Left/Right)
        self._hotkey_prev = QtWidgets.QShortcut(QtGui.QKeySequence("Ctrl+Left"), self._table_view)
        self._hotkey_prev.activated.connect(self._navigate_prev)

        self._hotkey_next = QtWidgets.QShortcut(QtGui.QKeySequence("Ctrl+Right"), self._table_view)
        self._hotkey_next.activated.connect(self._navigate_next)

        self._hotkey_next_in_function = QtWidgets.QShortcut(QtGui.QKeySequence("Ctrl+Shift+Right"), self._table_view)
        self._hotkey_next_in_function.activated.connect(self._navigate_next_in_function)

        self._hotkey_prev_in_function = QtWidgets.QShortcut(QtGui.QKeySequence("Ctrl+Shift+Left"), self._table_view)
        self._hotkey_prev_in_function.activated.connect(self._navigate_prev_in_function)

        self._hotkey_sync = QtWidgets.QShortcut(QtGui.QKeySequence("S"), self._table_view)
        self._hotkey_sync.activated.connect(self._sync_with_ida)

        self._hotkey_fuzz_target = QtWidgets.QShortcut(QtGui.QKeySequence("F"), self._table_view)
        self._hotkey_fuzz_target.activated.connect(self._navigate_best_fuzz_target)

    def _navigate_prev(self):
        """Navigate to previous BB row."""
        if not self._table_view or not self._table_model:
            return
        if not self._table_controller:
            return
        current = self._table_view.currentIndex()
        row = max(0, current.row() - 1)
        log_debug("_navigate_prev: Moving to row %d" % row)
        self._table_view.selectRow(row)
        self._table_controller.navigate_to_bb(row)

    def _navigate_next(self):
        """Navigate to next BB row."""
        if not self._table_view or not self._table_model:
            return
        if not self._table_controller:
            return
        current = self._table_view.currentIndex()
        row = min(self._table_model.rowCount() - 1, current.row() + 1)
        log_debug("_navigate_next: Moving to row %d" % row)
        self._table_view.selectRow(row)
        self._table_controller.navigate_to_bb(row)

    def _navigate_prev_in_function(self):
        """Navigate to previous BB in the current function."""
        if not self._table_view or not self._table_model or not self._table_controller:
            return

        current = self._table_view.currentIndex()
        if not current.isValid():
            return

        current_row = current.row()
        current_bb_address = self._table_model.row2bb.get(current_row, None)
        if current_bb_address is None:
            return

        director = self._table_model._director
        if not director:
            return

        funcs = director.metadata.get_functions_containing(current_bb_address)
        if not funcs:
            return

        target_function = funcs[0]

        for row in range(current_row - 1, -1, -1):
            bb_address = self._table_model.row2bb.get(row, None)
            if bb_address is None:
                continue

            bb_funcs = director.metadata.get_functions_containing(bb_address)
            if bb_funcs and bb_funcs[0] == target_function:
                log_debug("_navigate_prev_in_function: Moving to row %d" % row)
                self._table_view.selectRow(row)
                self._table_controller.navigate_to_bb(row)
                return

    def _navigate_next_in_function(self):
        """Navigate to next BB in the current function."""
        if not self._table_view or not self._table_model or not self._table_controller:
            return

        current = self._table_view.currentIndex()
        if not current.isValid():
            return

        current_row = current.row()
        current_bb_address = self._table_model.row2bb.get(current_row, None)
        if current_bb_address is None:
            return

        director = self._table_model._director
        if not director:
            return

        funcs = director.metadata.get_functions_containing(current_bb_address)
        if not funcs:
            return

        target_function = funcs[0]

        for row in range(current_row + 1, self._table_model.rowCount()):
            bb_address = self._table_model.row2bb.get(row, None)
            if bb_address is None:
                continue

            bb_funcs = director.metadata.get_functions_containing(bb_address)
            if bb_funcs and bb_funcs[0] == target_function:
                log_debug("_navigate_next_in_function: Moving to row %d" % row)
                self._table_view.selectRow(row)
                self._table_controller.navigate_to_bb(row)
                return

    def _on_refresh_clicked(self):
        """Handle refresh button click."""
        log_print("Refresh button clicked")
        self.refresh()
        if self._table_model:
            log_print("Refresh complete, row_count=%d" % self._table_model.rowCount())

    def _sync_with_ida(self):
        """Sync navigator with current IDA screen location."""
        if not self._table_view or not self._table_model or not self._table_controller:
            return

        try:
            current_address = disassembler[self.lctx].get_current_address()
        except:
            log_debug("_sync_with_ida: Failed to get current address")
            return

        if current_address == 0 or current_address == BADADDR:
            log_debug("_sync_with_ida: No valid current address")
            return

        director = self._table_model._director
        if not director:
            return

        # Find the function containing the current address
        funcs = director.metadata.get_functions_containing(current_address)
        if not funcs:
            log_debug("_sync_with_ida: No function contains current address 0x%X" % current_address)
            return

        target_function = funcs[0]
        best_row = -1
        min_distance = float('inf')

        # Find the BB in the model that's closest to our current address within the same function
        for row in range(self._table_model.rowCount()):
            bb_address = self._table_model.row2bb.get(row, None)
            if bb_address is None:
                continue

            bb_funcs = director.metadata.get_functions_containing(bb_address)
            if bb_funcs and bb_funcs[0] == target_function:
                # Check if this BB contains the current address or is nearby
                distance = abs(current_address - bb_address)
                if distance < min_distance:
                    min_distance = distance
                    best_row = row

        if best_row >= 0:
            log_debug("_sync_with_ida: Found BB at row %d (distance %d)" % (best_row, min_distance))
            self._table_view.selectRow(best_row)
            self._table_view.scrollTo(self._table_model.index(best_row, 0))
        else:
            log_debug("_sync_with_ida: No matching BB found for function %s" % target_function.name)

    def _navigate_best_fuzz_target(self):
        """
        Open a dialog ranking all covered functions by their trace span.

        The trace span of a function is measured from its first BB to its
        last BB in execution order. The function whose span covers the
        largest percentage of the whole trace is the best fuzzing target.
        """
        if not self._table_view or not self._table_model or not self._table_controller:
            return

        director = self._table_model._director
        if not director or not director.coverage:
            return

        metadata = director.metadata
        total_rows = self._table_model.rowCount()
        if total_rows == 0:
            return

        # For each function, find the first and last row in the trace
        # func_address -> (first_row, last_row)
        func_spans = {}

        for row in range(total_rows):
            bb_address = self._table_model.row2bb.get(row, None)
            if bb_address is None:
                continue

            bb_funcs = metadata.get_functions_containing(bb_address)
            if not bb_funcs:
                continue

            func_address = bb_funcs[0].address
            if func_address not in func_spans:
                func_spans[func_address] = (row, row)
            else:
                first_row = func_spans[func_address][0]
                func_spans[func_address] = (first_row, row)

        if not func_spans:
            log_debug("_navigate_best_fuzz_target: No function spans found")
            return

        # Build ranked list sorted by span descending
        ranked = []
        for func_address, (first_row, last_row) in func_spans.items():
            span = last_row - first_row + 1
            func_meta = metadata.functions.get(func_address, None)
            func_name = func_meta.name if func_meta else ("0x%X" % func_address)
            span_percent = float(span) / total_rows * 100.0
            ranked.append((func_name, func_address, span, span_percent, first_row))

        ranked.sort(key=lambda x: x[2], reverse=True)

        # Open the dialog
        dialog = FuzzTargetDialog(
            ranked, total_rows, self._table_view, self._table_model,
            self._table_controller, self.widget
        )
        dialog.exec_()

    def _update_status_label(self):
        """Update the status label with current BB count."""
        if not self._status_label or not self._table_model:
            return
        count = self._table_model.rowCount()
        text = "%d basic block%s" % (count, "s" if count != 1 else "")
        self._status_label.setText(text)
        log_debug("Status updated: %s" % text)

    def _ui_layout(self):
        if not self.widget or not self._table_view:
            return
        
        # Check if widget already has a layout
        existing_layout = self.widget.layout()
        if existing_layout:
            log_print("_ui_layout: WARNING - widget already has layout: %s" % existing_layout)
            # Clear the existing layout
            while existing_layout.count():
                item = existing_layout.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()
            QtWidgets.QWidget().setLayout(existing_layout)  # Orphan old layout
        
        layout = QtWidgets.QVBoxLayout()
        layout.setSpacing(int(get_dpi_scale()*5))
        layout.addWidget(self._toolbar)
        layout.addWidget(self._table_view, stretch=1)  # Give table stretch priority
        self.widget.setLayout(layout)
        log_print("_ui_layout: layout set, table_view.parent()=%s, widget=%s" % (
            self._table_view.parent(), self.widget))
        log_print("_ui_layout: table_view size=%s, viewport size=%s" % (
            self._table_view.size(), 
            self._table_view.viewport().size() if self._table_view.viewport() else "None"
        ))

    @disassembler.execute_ui
    def refresh(self):
        log_print("CoverageNavigator.refresh() called")
        if self._table_model:
            self._table_model.refresh()
        if self._table_view:
            # Debug: verify model connection
            view_model = self._table_view.model()
            log_print("CoverageNavigator.refresh(): view.model()=%s, our model=%s, same=%s" % (
                view_model, self._table_model, view_model is self._table_model))
            log_print("CoverageNavigator.refresh(): model.rowCount()=%d, model.columnCount()=%d" % (
                view_model.rowCount() if view_model else -1,
                view_model.columnCount() if view_model else -1))
            
            # Debug: check parent hierarchy
            log_print("CoverageNavigator.refresh(): table_view.parent()=%s, widget=%s" % (
                self._table_view.parent(), self.widget))
            log_print("CoverageNavigator.refresh(): table_view.isVisible()=%s, widget.isVisible()=%s" % (
                self._table_view.isVisible(), self.widget.isVisible() if self.widget else "N/A"))
            
            # Debug: manually test data() with a proper index
            if view_model and view_model.rowCount() > 0:
                test_index = view_model.index(1, 1)
                log_print("CoverageNavigator.refresh(): test_index valid=%s, row=%d, col=%d" % (
                    test_index.isValid(), test_index.row(), test_index.column()))
                test_data = view_model.data(test_index, QtCore.Qt.DisplayRole)
                log_print("CoverageNavigator.refresh(): data(1,1)='%s'" % test_data)
            
            # Force the view to reset and re-query the model
            self._table_view.reset()
            self._table_view.viewport().update()
            log_print("CoverageNavigator.refresh(): view reset, viewport size=%s" % self._table_view.viewport().size())
        self._update_status_label()

    @disassembler.execute_ui
    def refresh_theme(self):
        if self._table_view:
            self._table_view.refresh_theme()
        if self._table_model:
            self._table_model.refresh_theme()

#------------------------------------------------------------------------------
# Qt Event Filter for Navigator
#------------------------------------------------------------------------------

class NavigatorEventProxy(QtCore.QObject):
    EventShow = 17
    EventDestroy = 16
    EventResize = 14

    def __init__(self, target):
        super(NavigatorEventProxy, self).__init__()
        self._target = weakref.proxy(target) if target else None
        self._first_show = True

    def eventFilter(self, source, event):
        event_type = int(event.type())
        
        if event_type == self.EventDestroy:
            source.removeEventFilter(self)
            if self._target:
                self._target.terminate()
        
        # Refresh when widget is first shown or resized
        elif event_type == self.EventShow and self._first_show:
            self._first_show = False
            log_print("EventProxy: First show event, refreshing...")
            if self._target:
                self._target.refresh()
        
        elif event_type == self.EventResize:
            log_print("EventProxy: Resize event")
            
        return False
