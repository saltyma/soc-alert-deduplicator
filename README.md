# SOC Alert Deduplicator

A Python-based tool designed to reduce alert fatigue by clustering repetitive SOC alerts into incident-oriented summaries.

## Problem
Security analysts often receive repeated alerts for the same host, user, process or file hash. This creates fatigue and slows down triage.
This tool aims to reduce alert noise by grouping duplicate or highly similar alerts into incident-oriented summaries.

## Target users
- SOC analysts who need faster alert triage
- SOC admins or detection enginners who need configurable grouping rules

## Status
Project setup in progress

## Planned features
- Parse JSON alerts
- Normalize alert fields
- Group duplicate or near-duplicate alerts
- Produce concise incident summaries
- Support configurable grouping rules
