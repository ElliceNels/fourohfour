class GenerationError(Exception):
    def __init__(self):
        self.message = "Error generating data"
        super().__init__(self.message)

class RegistrationError(Exception):
    def __init__(self):
        self.message = "Error registering user"
        super().__init__(self.message)