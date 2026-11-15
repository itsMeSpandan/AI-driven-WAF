# Third-Party Software, Datasets and Licenses

This project incorporates and builds upon open-source software libraries, containerized baselines, and public security research datasets. All third-party dependencies are licensed under permissive open-source licenses allowing educational, research, and non-commercial development.

---

## 1. Datasets and Attack Corpora

| Component / Corpus | Source / Repository | Original Authors / Maintainers | License | Intended Use in Project |
|:---|:---|:---|:---:|:---|
| **PayloadsAllTheThings** | `https://github.com/swisskyrepo/PayloadsAllTheThings` | Swissky and Contributors | MIT License | Injection payload collection for SQLi, XSS, and Path Traversal training and testing. |
| **SecLists** | `https://github.com/danielmiessler/SecLists` | Daniel Miessler, Jason Haddix | MIT License | Malicious payload lists, evasion vectors, and common parameter probes. |
| **CSIC 2010 HTTP Dataset** | `http://www.isi.csic.es/dataset/` | Information Security Institute of CSIC (Spain) | Open Academic Research License | Independent out-of-distribution benign and anomalous eCommerce HTTP traffic. |
| **OWASP Juice Shop** | `https://github.com/juice-shop/juice-shop` | Björn Kimminich, OWASP Foundation | MIT License | Realistic vulnerable web application used as upstream reverse-proxy target. |

---

## 2. Containerized Baselines

| Component | Source Image / Repository | License | Role in Evaluation |
|:---|:---|:---:|:---|
| **OWASP ModSecurity Core Rule Set (CRS v4.8.0)** | `owasp/modsecurity-crs:4.8.0-apache-202410200812` (`https://coreruleset.org`) | Apache License 2.0 | Standard industry regex WAF baseline for detection and latency benchmarking. |
| **ModSecurity Engine (v3 / v2.9)** | `https://github.com/owasp-modsecurity/ModSecurity` | Apache License 2.0 | Underlying WAF inspection module integrated with Apache HTTP Server. |

---

## 3. Python Backend & ML Dependencies

All Python packages are installed via standard package management (`pip`) with permissive open-source licenses:

| Package | Upstream URL | License | Purpose in Project |
|:---|:---|:---:|:---|
| **FastAPI** | `https://github.com/tiangolo/fastapi` | MIT License | High-performance asynchronous API framework for Gateway proxy and Dashboard API. |
| **Uvicorn** | `https://github.com/encode/uvicorn` | BSD 3-Clause | ASGI server implementation for FastAPI services. |
| **httpx** | `https://github.com/encode/httpx` | BSD 3-Clause | Asynchronous HTTP client for reverse-proxy request forwarding and test clients. |
| **scikit-learn** | `https://github.com/scikit-learn/scikit-learn` | BSD 3-Clause | Machine learning pipeline: `FeatureUnion`, `TfidfVectorizer`, `LogisticRegression`. |
| **numpy** | `https://github.com/numpy/numpy` | BSD 3-Clause | High-performance array operations and numerical statistical routines. |
| **scipy** | `https://github.com/scipy/scipy` | BSD 3-Clause | Sparse matrix computation and feature mapping. |
| **joblib** | `https://github.com/joblib/joblib` | BSD 3-Clause | Efficient serialization and deserialization of trained ML pipelines. |
| **SQLAlchemy** | `https://github.com/sqlalchemy/sqlalchemy` | MIT License | SQL toolkit and Object-Relational Mapping (ORM) for event persistence. |
| **pydantic** | `https://github.com/pydantic/pydantic` | MIT License | Data validation and settings management using Python type annotations. |
| **python-docx** | `https://github.com/python-openxml/python-docx` | MIT License | Programmatic Microsoft Word DOCX document generation for the final academic report. |
| **matplotlib** | `https://github.com/matplotlib/matplotlib` | PSF License | Figure generation for confusion matrices, latency curves, and system diagrams. |
| **shap** | `https://github.com/shap/shap` | MIT License | Game-theoretic SHAP explanations for interpretability validation studies. |
| **pytest** | `https://github.com/pytest-dev/pytest` | MIT License | Unit, integration, and security regression testing framework. |
| **pytest-cov** | `https://github.com/pytest-dev/pytest-cov` | MIT License | Code coverage measurement across gateway, dashboard, and ML modules. |
| **ruff** | `https://github.com/astral-sh/ruff` | MIT License | Python code linter and code quality scanner. |

---

## 4. Frontend & JavaScript Dependencies

All JavaScript and UI libraries are managed via `npm` in `dashboard/ui/`:

| Package | Upstream URL | License | Purpose in Project |
|:---|:---|:---:|:---|
| **Next.js (v14.1.0)** | `https://github.com/vercel/next.js` | MIT License | React application framework for Server-Side Rendering (SSR) and client navigation. |
| **React & React-DOM (v18.2.0)** | `https://github.com/facebook/react` | MIT License | Declarative user interface component library. |
| **Tailwind CSS (v3.4.1)** | `https://github.com/tailwindlabs/tailwindcss` | MIT License | Utility-first CSS framework for responsive dark-mode SecOps styling. |
| **Recharts (v2.12.0)** | `https://github.com/recharts/recharts` | MIT License | Composable charting library for real-time Traffic vs Threats visualisations. |
| **Lucide React (v0.330.0)** | `https://github.com/lucide-icons/lucide` | ISC License | Scalable vector icons for dashboard status badges and navigation menus. |
| **axios (v1.6.7)** | `https://github.com/axios/axios` | MIT License | Promise-based HTTP client for browser API interactions. |

---

## 5. Permissive Licensing Confirmation

All datasets, container base images, and software libraries utilized across this repository are confirmed to be licensed under permissive licenses (MIT, Apache 2.0, BSD 3-Clause, ISC, PSF). No components require reciprocal copyleft licensing (such as GPL v3 or AGPL), ensuring clean redistribution, academic submission, and future commercial or open-source deployment.
