## Training Web Application

Built in three distinct phases, each stored in their respective folders for the purposes of demonstrating code development and review using an LLM.
All use a local Docker environment for testing purposes. 
The intent for demonstration will be in between phases. The expectation is that each phase is a launch point for the real exercise - code review the state of the repository at that time, and post comments to a PR for suggested updates. 

There are two personas:
- Submitting developer - A junior developer who is writing all the code. Is not actually aware the code is flawed as it is being written.
- Reviewing developer - A senior developer who is code reviewing the PR submissions of the junior developer. 

### Phase 1

Deploy a basic React.js frontend web application. 
The features are irrelevant - the exercise is about adding new features and verifying function.
Only a splash page with a large, centered button is required. 
In Phase 1, this Button should be labeled "Who am I?" - pressing it returns an error, as there is no feature or call implemented behind it.
No tests written yet.
Create all required Docker setup.

### Phase 2

Modify Phase 1, adding user authentication. 
Since this is an entirely local, demo testing environment, auth should be mostly contrived - an e-mail address + password to login. 
The Button "Who am I?" should now be fixed, and return the identity of the logged in user.  
Crucially however, the auth should have an intentional vulnerability.
This vulnerability should allow me to login as _any_ user, WITHOUT the appropriate password. 
This should be written as a poorly written auth check for the user and password.
No tests are written yet. 

### Phase 3

Modify Phase 2, fixing user authentication.
Add tests to validate and prevent regression.

