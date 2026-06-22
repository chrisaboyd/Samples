import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';
import App from './App';

describe('Authentication', () => {
  test('login form is displayed on initial load', () => {
    render(<App />);
    expect(screen.getByText('Login')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Email')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Password')).toBeInTheDocument();
  });

  test('successful login with correct credentials', () => {
    render(<App />);
    
    fireEvent.change(screen.getByPlaceholderText('Email'), {
      target: { value: 'alice@example.com' }
    });
    fireEvent.change(screen.getByPlaceholderText('Password'), {
      target: { value: 'alice123' }
    });
    fireEvent.click(screen.getByText('Log In'));
    
    expect(screen.getByText('Who am I?')).toBeInTheDocument();
  });

  test('failed login with wrong password is rejected', () => {
    render(<App />);
    
    // Mock window.alert
    window.alert = jest.fn();
    
    fireEvent.change(screen.getByPlaceholderText('Email'), {
      target: { value: 'alice@example.com' }
    });
    fireEvent.change(screen.getByPlaceholderText('Password'), {
      target: { value: 'wrongpassword' }
    });
    fireEvent.click(screen.getByText('Log In'));
    
    expect(window.alert).toHaveBeenCalledWith('Invalid credentials');
    expect(screen.queryByText('Who am I?')).not.toBeInTheDocument();
  });

  test('failed login with non-existent email is rejected', () => {
    render(<App />);
    
    window.alert = jest.fn();
    
    fireEvent.change(screen.getByPlaceholderText('Email'), {
      target: { value: 'nonexistent@example.com' }
    });
    fireEvent.change(screen.getByPlaceholderText('Password'), {
      target: { value: 'anypassword' }
    });
    fireEvent.click(screen.getByText('Log In'));
    
    expect(window.alert).toHaveBeenCalledWith('Invalid credentials');
  });

  test('"Who am I?" button shows logged in user name', () => {
    render(<App />);
    
    window.alert = jest.fn();
    
    // Login as Bob
    fireEvent.change(screen.getByPlaceholderText('Email'), {
      target: { value: 'bob@example.com' }
    });
    fireEvent.change(screen.getByPlaceholderText('Password'), {
      target: { value: 'bob456' }
    });
    fireEvent.click(screen.getByText('Log In'));
    
    // Click Who am I?
    fireEvent.click(screen.getByText('Who am I?'));
    
    expect(window.alert).toHaveBeenCalledWith('You are logged in as: Bob');
  });

  test('logout clears the session', () => {
    render(<App />);
    
    // Login first
    fireEvent.change(screen.getByPlaceholderText('Email'), {
      target: { value: 'alice@example.com' }
    });
    fireEvent.change(screen.getByPlaceholderText('Password'), {
      target: { value: 'alice123' }
    });
    fireEvent.click(screen.getByText('Log In'));
    
    expect(screen.getByText('Who am I?')).toBeInTheDocument();
    
    // Logout
    fireEvent.click(screen.getByText('Logout'));
    
    expect(screen.getByText('Login')).toBeInTheDocument();
    expect(screen.queryByText('Who am I?')).not.toBeInTheDocument();
  });
});