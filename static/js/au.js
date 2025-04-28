document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const loginTab = document.getElementById('loginTab');
    const signupTab = document.getElementById('signupTab');
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');
    const authBox = document.getElementById('authBox');
    const successMessage = document.getElementById('successMessage');
    const errorMessage = document.getElementById('errorMessage');
    const userGreeting = document.getElementById('userGreeting');
    const rememberMe = document.getElementById('rememberMe');

    // Tab switching
    loginTab.addEventListener('click', function() {
        loginTab.classList.add('active');
        signupTab.classList.remove('active');
        loginForm.classList.add('active');
        signupForm.classList.remove('active');
    });

    signupTab.addEventListener('click', function() {
        signupTab.classList.add('active');
        loginTab.classList.remove('active');
        signupForm.classList.add('active');
        loginForm.classList.remove('active');
    });

    // Form submissions
    loginForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const email = document.getElementById('loginEmail').value;
        const password = document.getElementById('loginPassword').value;
        
        if (!validateEmail(email)) {
            showError('Please enter a valid email address');
            return;
        }
        
        if (password.length < 6) {
            showError('Password must be at least 6 characters');
            return;
        }
        
        // Simulate login (in a real app, this would be an API call)
        simulateLogin(email, password);
    });

    signupForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const name = document.getElementById('signupName').value;
        const email = document.getElementById('signupEmail').value;
        const password = document.getElementById('signupPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;
        
        if (name.trim() === '') {
            showError('Please enter your full name');
            return;
        }
        
        if (!validateEmail(email)) {
            showError('Please enter a valid email address');
            return;
        }
        
        if (password.length < 6) {
            showError('Password must be at least 6 characters');
            return;
        }
        
        if (password !== confirmPassword) {
            showError('Passwords do not match');
            return;
        }
        
        // Simulate signup (in a real app, this would be an API call)
        simulateSignup(name, email, password);
    });

    // Helper functions
    function validateEmail(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    }

    function showError(message) {
        errorMessage.textContent = message;
        errorMessage.style.display = 'block';
        
        setTimeout(() => {
            errorMessage.style.display = 'none';
        }, 5000);
    }

    function simulateLogin(email, password) {
        // In a real app, you would make an API call here
        // This is just a simulation
        
        // Check if user exists in localStorage
        const users = JSON.parse(localStorage.getItem('masterErrorUsers')) || [];
        const user = users.find(u => u.email === email);
        
        if (!user) {
            showError('User not found');
            return;
        }
        
        // In a real app, you would compare hashed passwords
        if (user.password !== password) {
            showError('Incorrect password');
            return;
        }
        
        // Login successful
        if (rememberMe.checked) {
            localStorage.setItem('masterErrorRememberedEmail', email);
        } else {
            localStorage.removeItem('masterErrorRememberedEmail');
        }
        
        showSuccess(user.name);
    }

    function simulateSignup(name, email, password) {
        // In a real app, you would make an API call here
        // This is just a simulation
        
        // Check if user already exists
        const users = JSON.parse(localStorage.getItem('masterErrorUsers')) || [];
        const userExists = users.some(u => u.email === email);
        
        if (userExists) {
            showError('User with this email already exists');
            return;
        }
        
        // In a real app, you would hash the password before storing
        const newUser = { name, email, password };
        users.push(newUser);
        localStorage.setItem('masterErrorUsers', JSON.stringify(users));
        
        showSuccess(name);
    }

    function showSuccess(name) {
        authBox.style.display = 'none';
        userGreeting.textContent = name;
        successMessage.style.display = 'flex';
        
        // Simulate redirect (in a real app, this would redirect to dashboard)
        setTimeout(() => {
            alert(`In a real application, you would now be redirected to the dashboard.`);
            // window.location.href = '/dashboard';
        }, 3000);
    }

    // Check for remembered email
    const rememberedEmail = localStorage.getItem('masterErrorRememberedEmail');
    if (rememberedEmail) {
        document.getElementById('loginEmail').value = rememberedEmail;
        rememberMe.checked = true;
    }
});

// Toggle password visibility
function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    const icon = input.nextElementSibling.querySelector('i');
    
    if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    }
}