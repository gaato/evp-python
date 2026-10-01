"""Sphinx configuration."""

from __future__ import annotations

from importlib.metadata import version as _version

project = "evp"
author = "Gakuto Furuya"
copyright = f"2026, {author}"
release = _version("evp")
version = ".".join(release.split(".")[:2])

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
]

source_suffix = {".md": "markdown", ".rst": "restructuredtext"}
exclude_patterns = ["_build"]

myst_enable_extensions = ["colon_fence", "deflist", "fieldlist"]
myst_heading_anchors = 3

autodoc_member_order = "bysource"
autodoc_typehints = "description"
autodoc_typehints_description_target = "documented_params"
autodoc_default_options = {"members": True, "show-inheritance": True}
autodoc_preserve_defaults = True

intersphinx_mapping = {"python": ("https://docs.python.org/3", None)}

html_theme = "furo"
html_title = f"evp {release}"
html_theme_options = {
    "source_repository": "https://github.com/gaato/evp-python/",
    "source_branch": "main",
    "source_directory": "docs/",
}
