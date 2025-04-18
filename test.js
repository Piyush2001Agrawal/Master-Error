document.addEventListener('DOMContentLoaded', function() {
    // Initialize CodeMirror
    const editor = CodeMirror(document.getElementById('code-editor'), {
        lineNumbers: true,
        theme: 'dracula',
        mode: 'python',
        indentUnit: 4,
        tabSize: 4,
        lineWrapping: true,
        autoCloseBrackets: true,
        matchBrackets: true,
        extraKeys: {
            "Ctrl-Enter": runCode,
            "Shift-Enter": analyzeCode
        } 
    });

    // Set initial code
    editor.setValue(# Welcome to Master Error IDE\n# Try writing some code and click "Run"\n\ndef greet(name):\n    print(f"Hello, {name}!")\n\ngreet("Developer"));

    // Language selector
    const languageSelector = document.getElementById('language-selector');
    languageSelector.addEventListener('change', function() {
        const modeMap = {
            'python': 'python',
            'javascript': 'javascript',
            'java': 'text/x-java',
            'cpp': 'text/x-c++src',
            'htmlmixed': 'htmlmixed',
            'css': 'css'
        };
        editor.setOption('mode', modeMap[this.value]);
    });

    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            this.classList.add('active');
            document.getElementById(${this.dataset.tab}-content).classList.add('active');
        });
    });

    // Button event handlers
    document.getElementById('run-btn').addEventListener('click', runCode);
    document.getElementById('analyze-btn').addEventListener('click', analyzeCode);
    document.getElementById('clear-btn').addEventListener('click', clearCode);
    document.getElementById('save-btn').addEventListener('click', saveCode);

    async function runCode() {
        const code = editor.getValue();
        if (!code.trim()) return;
        
        document.querySelector('[data-tab="output"]').click();
        document.getElementById('output-content').textContent = 'Executing code...';
        
        try {
            const response = await fetch('/execute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code, language: languageSelector.value })
            });
            
            const data = await response.json();
            document.getElementById('output-content').innerHTML = data.output;
        } catch (error) {
            document.getElementById('output-content').textContent = 'Error: ' + error.message;
        }
    }

    async function analyzeCode() {
        const code = editor.getValue();
        if (!code.trim()) return;
        
        document.querySelector('[data-tab="errors"]').click();
        document.getElementById('errors-content').textContent = 'Analyzing code...';
        
        try {
            const response = await fetch('/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code, language: languageSelector.value })
            });
            
            const data = await response.json();
            document.getElementById('errors-content').innerHTML = data.errors;
            document.getElementById('suggestions-content').innerHTML = data.suggestions;
        } catch (error) {
            document.getElementById('errors-content').textContent = 'Error: ' + error.message;
        }
    }

    function clearCode() {
        if (confirm('Are you sure you want to clear the editor?')) {
            editor.setValue('');
        }
    }

    function saveCode() {
        const code = editor.getValue();
        const blob = new Blob([code], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = code-${new Date().toISOString().slice(0,10)}.${languageSelector.value};
        a.click();
        URL.revokeObjectURL(url);
    }
});