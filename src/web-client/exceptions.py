class GenerationError(Exception):
    def __init__(self):
        self.message = "Error generating data"
        super().__init__(self.message)

class RegistrationError(Exception):
    def __init__(self):
        self.message = "Error registering user"
        super().__init__(self.message)
    
class UserNotFoundError(Exception):
    def __init__(self):
        self.message = "User not found"
        super().__init__(self.message)

class InvalidPasswordError(Exception):
    def __init__(self):
        self.message = "Invalid password"
        super().__init__(self.message)

class UsernameAlreadyExistsError(Exception):
    def __init__(self):
        self.message = "Username already exists"
        super().__init__(self.message)

class ServerError(Exception):
    def __init__(self):
        self.message = "Server error occurred"
        super().__init__(self.message)

class SamePasswordError(Exception):
    def __init__(self):
        self.message = "New password is same as old password"
        super().__init__(self.message)
