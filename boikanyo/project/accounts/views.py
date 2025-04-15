from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
# Register view
def register(request):
    if request.method == 'POST':
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        username = request.POST['username']
        email = request.POST['email']
        password1 = request.POST['password1']
        password2 = request.POST['password2']

        # Validation
        if password1 != password2:
            return render(request, 'register.html', {'error': 'Passwords do not match.'})
        if User.objects.filter(username=username).exists():
            return render(request, 'register.html', {'error': 'Username already exists.'})
        if User.objects.filter(email=email).exists():
            return render(request, 'register.html', {'error': 'Email already exists.'})
        if len(username) < 5:
            return render(request, 'register.html', {'error': 'Username must be at least 5 characters long.'})
        if not any(char.isalpha() for char in password1):
            return render(request, 'register.html', {'error': 'Password must contain at least one letter.'})

        # Create user
        user = User.objects.create_user(
            username=username,
            password=password1,
            email=email,
            first_name=first_name,
            last_name=last_name
        )
        user.save()
        print("User created")
        return redirect('login')
    else:
        return render(request, 'register.html')


# Login view

def login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(request, username=username, password=password)
        if user is not None:
            auth_login(request, user)
            return redirect('/')  # Redirect to home page or dashboard
        else:
            return render(request, 'login.html', {'error': 'Invalid username or password.'})
    else:
        return render(request, 'login.html')
    
def logout(request):
    if request.method == 'POST':
        auth_logout(request)
        return redirect('/')  # Redirect to login page after logout
    else:
        return render(request, 'login.html')  # Render login page if not a POST request