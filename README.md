# SOAR Lite: IP Enrichment & SOC Summary (Python)

## Overview
This project demonstrates a lightweight SOAR-style enrichment workflow used in SOC triage. Given an IP address, the tool enriches it with network/geo context, produces a SOC-ready assessment (severity, confidence, recommended action), and saves a structured JSON report for case documentation.

## What It Does
- Enriches an IP with geo/org/ASN context
- Produces a SOC-style summary (severity, confidence, action + rationale)
- Writes a JSON report for evidence and repeatable workflows
- Includes sample output and a SOC case-notes template

## Repository Structure
- main.py — enrichment + SOC assessment + report output
- sample_outputs/ — example JSON reports
- case_notes/ — SOC case notes template
- evidence/ — screenshots for portfolio proof

## Install
pip3 install -r requirements.txt

## Run
python3 main.py 8.8.8.8

## Output
- Terminal SOC-style enrichment summary
- JSON report saved under outputs/

## SOC Use Case
Simulates a Tier-1 workflow where an analyst receives an IP from logs and needs quick enrichment and a documented decision.
