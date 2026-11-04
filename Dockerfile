FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt \
    && groupadd --gid 10001 exporter \
    && useradd --uid 10001 --gid exporter --create-home exporter

COPY --chown=exporter:exporter wiz_two_menu_export.py resource_groups.json tenant_profiles.json ./
COPY --chown=exporter:exporter queries/ ./queries/

RUN mkdir /app/reports && chown exporter:exporter /app/reports
USER exporter

ENTRYPOINT ["python", "wiz_two_menu_export.py"]
