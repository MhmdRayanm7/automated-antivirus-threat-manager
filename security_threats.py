import abc
from datetime import datetime


class Threat(abc.ABC):
    """
    Base class for all security threats.
    in: filename, file_size_kb, base_danger_score
    out: threat object
    """

    def __init__(self, filename: str, file_size_kb: int, base_danger_score: float):
        """
        in: filename, file_size_kb, base_danger_score
        out: None
        """
        if not filename:
            raise ValueError("Filename cannot be empty.")

        if file_size_kb <= 0:
            raise ValueError("File size must be greater than zero.")

        self._filename = filename
        self._file_size_kb = int(file_size_kb)
        self._base_danger_score = float(base_danger_score)

        # Danger score is private and can only be changed through the property.
        self.__danger_score = 0
        self.danger_score = base_danger_score

    @property
    def filename(self) -> str:
        """
        in: None
        out: filename
        """
        return self._filename

    @property
    def file_size_kb(self) -> int:
        """
        in: None
        out: file size in KB
        """
        return self._file_size_kb

    @property
    def danger_score(self) -> int:
        """
        in: None
        out: danger score
        """
        return self.__danger_score

    @danger_score.setter
    def danger_score(self, value: float):
        """
        in: value
        out: None
        """
        if value < 0 or value > 100:
            raise ValueError("Danger score must be between 0 and 100.")

        self.__danger_score = int(value)
        self._base_danger_score = float(value)

    @abc.abstractmethod
    def assess_risk_level(self) -> float:
        """
        in: None
        out: calculated risk level
        """
        pass

    @abc.abstractmethod
    def generate_signature(self) -> str:
        """
        in: None
        out: threat signature
        """
        pass

    def __str__(self) -> str:
        """
        in: None
        out: formatted threat information
        """
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return (
            f"{scan_time} | "
            f"{self.__class__.__name__} | "
            f"{self._filename} | "
            f"{self._file_size_kb} KB | "
            f"danger={self.danger_score}"
        )


class RansomwareVirus(Threat):
    """
    Ransomware threat class.
    in: filename, file_size_kb, base_danger_score, target_directory
    out: ransomware object
    """

    def __init__(
        self,
        filename: str,
        file_size_kb: int,
        base_danger_score: float,
        target_directory: str
    ):
        """
        in: filename, file_size_kb, base_danger_score, target_directory
        out: None
        """
        super().__init__(filename, file_size_kb, base_danger_score)

        if not target_directory:
            raise ValueError("Target directory cannot be empty.")

        self.target_directory = target_directory

    def assess_risk_level(self) -> float:
        """
        in: None
        out: calculated risk level
        """
        directory = self.target_directory.lower()
        multiplier = 1.0

        # System folders make ransomware more dangerous.
        if "system32" in directory:
            multiplier = 2.5
        elif "windows" in directory:
            multiplier = 2.0
        elif "system" in directory:
            multiplier = 1.5

        return float(self.danger_score * multiplier)

    def generate_signature(self) -> str:
        """
        in: None
        out: threat signature
        """
        return f"RANSOM-{self._filename}-{self._file_size_kb}"


class SpywareVirus(Threat):
    """
    Spyware threat class.
    in: filename, file_size_kb, base_danger_score, data_target, network_access
    out: spyware object
    """

    def __init__(
        self,
        filename: str,
        file_size_kb: int,
        base_danger_score: float,
        data_target: str,
        network_access: bool
    ):
        """
        in: filename, file_size_kb, base_danger_score, data_target, network_access
        out: None
        """
        super().__init__(filename, file_size_kb, base_danger_score)

        if not data_target:
            raise ValueError("Data target cannot be empty.")

        self.data_target = data_target
        self.network_access = bool(network_access)

    def assess_risk_level(self) -> float:
        """
        in: None
        out: calculated risk level
        """
        target = self.data_target.lower()
        risk = float(self.danger_score)

        # Network access increases the chance of data stealing.
        if self.network_access:
            risk *= 1.7

        if "password" in target or "credential" in target or "bank" in target:
            risk *= 2.0
        elif "cookie" in target or "browser" in target:
            risk *= 1.5

        return risk

    def generate_signature(self) -> str:
        """
        in: None
        out: threat signature
        """
        return f"SPY-{self._filename}-{self.data_target}"