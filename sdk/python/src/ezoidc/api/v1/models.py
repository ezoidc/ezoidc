"""ezoidc v1.0 API models."""

from typing import Any

from pydantic import BaseModel


class VariableValue(BaseModel):
    string: str = ""


class Variable(BaseModel):
    name: str = ""
    value: VariableValue | None = None
    export: str | None = None
    redact: bool | None = None

    @property
    def string(self) -> str:
        return self.value.string if self.value else ""


class MetadataResponse(BaseModel):
    ezoidc: bool
    api_version: str


class VariablesRequest(BaseModel):
    params: dict[str, Any] | None = None


class VariablesResponse(BaseModel):
    variables: list[Variable] = []

    def environ(self) -> dict[str, str]:
        """
        Return a dict of exportable variable names to their string values.
        """
        return {v.export: v.string for v in self.variables if v.export}

    def names(self) -> list[str]:
        """
        Return a list of variable names.
        """
        return [v.name for v in self.variables]


class ErrorResponse(BaseModel):
    error: str
    reason: str = ""
