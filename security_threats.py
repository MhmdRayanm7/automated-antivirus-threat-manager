import abc
from datetime import datetime


class Threat(abc.ABC):
    """
    Base threat class.
    in: filename, file_size_kb, base_danger_score
    out: Threat object
    """

    def __init__(self, filename, file_size_kb, base_danger_score):
        """
        in: filename, file_size_kb, base_danger_score
        out: None
        """
        self._filename = filename
        self._file_size_kb = file_size_kb
        self._base_danger_score = base_danger_score
        self.__danger_score = 0
        self.danger_score = base_danger_score

    @property
    def danger_score(self):
        """
        in: None
        out: danger score
        """
        return self.__danger_score

    @danger_score.setter
    def danger_score(self, value):
        """
        in: value
        out: None
        """
        if value < 0 or value > 100:
            raise ValueError("Danger score must be between 0 and 100.")

        self.__danger_score = int(value)

    @abc.abstractmethod
    def assess_risk_level(self):
        """
        in: None
        out: risk level
        """
        pass

    @abc.abstractmethod
    def generate_signature(self):
        """
        in: None
        out: signature
        """
        pass

    def __str__(self):
        """
        in: None
        out: threat information
        """
        return f"{datetime.now()} | {self._filename} | {self.danger_score}"


class RansomwareVirus(Threat):
    """
    Ransomware threat.
    in: filename, file_size_kb, base_danger_score, target_directory
    out: RansomwareVirus object
    """

    def __init__(self, filename, file_size_kb, base_danger_score, target_directory):
        """
        in: filename, file_size_kb, base_danger_score, target_directory
        out: None
        """
        super().__init__(filename, file_size_kb, base_danger_score)
        self.target_directory = target_directory

    def assess_risk_level(self):
        """
        in: None
        out: risk level
        """
        risk = self.danger_score

        if "system32" in self.target_directory.lower():
            risk = risk * 2.5
        elif "windows" in self.target_directory.lower():
            risk = risk * 2
        elif "system" in self.target_directory.lower():
            risk = risk * 1.5

        return risk

    def generate_signature(self):
        """
        in: None
        out: signature
        """
        return f"RANSOM-{self._filename}-{self._file_size_kb}"