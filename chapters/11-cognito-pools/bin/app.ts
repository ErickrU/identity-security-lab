#!/usr/bin/env node
import { App } from 'aws-cdk-lib';
import { CognitoPoolsStack } from '../lib/cognito-pools-stack';

const app = new App();

// Intentionally omit `env`: synthesis is offline and deployment uses the
// account and Region selected by the reader's CDK/AWS credentials.
new CognitoPoolsStack(app, 'LabCognitoPools', {
  description: 'LAB ONLY: Cognito user pool + identity pool with per-identity S3 access',
});

app.synth();
