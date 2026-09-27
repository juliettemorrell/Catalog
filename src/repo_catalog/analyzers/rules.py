"""Knowledge base: which dependencies and files imply which technologies and capabilities.

The tables are plain text so they are easy to extend without touching code. Each line:

    category | Label | capability, capability | dep-name, other-dep, prefix*

``category`` maps to a field on ``models.Stack``. Capabilities are free-form tags that
answer "which repos already do X?" for the SDLC agent (e.g. ``payments``, ``pdf``).
Dependency names are matched case-insensitively; ``_`` and ``-`` are equivalent; a
trailing ``*`` is a prefix match. Maven uses ``group:artifact``; Go uses module paths.
"""

from __future__ import annotations

from dataclasses import dataclass

_DEPENDENCY_TABLE = """
# ---- web / app frameworks -------------------------------------------------------------
frameworks | React | frontend, ui | react
frameworks | Next.js | frontend, ssr, web-app | next
frameworks | Remix | frontend, ssr | @remix-run/react, @remix-run/node
frameworks | React Router | frontend, routing | react-router, react-router-dom
frameworks | Vue | frontend, ui | vue
frameworks | Nuxt | frontend, ssr | nuxt
frameworks | Angular | frontend, ui | @angular/core
frameworks | Svelte | frontend, ui | svelte
frameworks | SvelteKit | frontend, ssr | @sveltejs/kit
frameworks | Solid | frontend, ui | solid-js
frameworks | Astro | frontend, static-site | astro
frameworks | Gatsby | frontend, static-site | gatsby
frameworks | Qwik | frontend | @builder.io/qwik
frameworks | Preact | frontend, ui | preact
frameworks | Lit | frontend, web-components | lit
frameworks | Electron | desktop-app | electron
frameworks | Tauri | desktop-app | @tauri-apps/api, tauri
frameworks | React Native | mobile | react-native
frameworks | Expo | mobile | expo
frameworks | Ionic | mobile | @ionic/core, @ionic/react, @ionic/angular
frameworks | Flutter | mobile | flutter
frameworks | Android | mobile | com.android.application*, com.android.tools.build:gradle
frameworks | Jetpack Compose | mobile, ui | androidx.compose*
frameworks | .NET MAUI | mobile, desktop-app | microsoft.maui.controls*
frameworks | Express | rest-api, backend | express
frameworks | Fastify | rest-api, backend | fastify
frameworks | NestJS | rest-api, backend | @nestjs/core
frameworks | Koa | rest-api, backend | koa
frameworks | Hono | rest-api, backend | hono
frameworks | Hapi | rest-api, backend | @hapi/hapi
frameworks | tRPC | rpc-api, backend | @trpc/server
frameworks | Apollo Server | graphql-api, backend | @apollo/server, apollo-server, apollo-server-express
frameworks | GraphQL Yoga | graphql-api, backend | graphql-yoga
frameworks | Socket.IO | realtime | socket.io, socket.io-client
frameworks | FastAPI | rest-api, backend | fastapi
frameworks | Django | web-app, backend, orm | django
frameworks | Django REST Framework | rest-api | djangorestframework
frameworks | Flask | rest-api, backend | flask
frameworks | Starlette | rest-api, backend | starlette
frameworks | Litestar | rest-api, backend | litestar
frameworks | aiohttp | backend, http-client | aiohttp
frameworks | Tornado | backend | tornado
frameworks | Streamlit | dashboard, data-app | streamlit
frameworks | Gradio | data-app, ml-demo | gradio
frameworks | Dash | dashboard, data-app | dash
frameworks | Panel | dashboard, data-app | panel
frameworks | Reflex | web-app | reflex
frameworks | Typer | cli | typer
frameworks | Click | cli | click
frameworks | Celery | background-jobs, queue | celery
frameworks | Spring Boot | rest-api, backend | org.springframework.boot:*
frameworks | Spring | backend | org.springframework:*
frameworks | Quarkus | backend | io.quarkus:*
frameworks | Micronaut | backend | io.micronaut:*
frameworks | Ktor | backend | io.ktor:*
frameworks | Gin | rest-api, backend | github.com/gin-gonic/gin
frameworks | Echo | rest-api, backend | github.com/labstack/echo*
frameworks | Fiber | rest-api, backend | github.com/gofiber/fiber*
frameworks | Chi | rest-api, backend | github.com/go-chi/chi*
frameworks | gRPC | rpc-api | grpc.aspnetcore*, grpc-server, @grpc/grpc-js-server
# client/runtime libraries: stack.py promotes them to the gRPC framework when the repo
# defines its own services in .proto files (a client alone is not an API)
libraries | gRPC | rpc-client | grpc, @grpc/grpc-js, grpcio, google.golang.org/grpc, io.grpc:*, grpc.net.client*, grpc.core*
frameworks | Cobra | cli | github.com/spf13/cobra
frameworks | Actix | rest-api, backend | actix-web
frameworks | Axum | rest-api, backend | axum
frameworks | Rocket | rest-api, backend | rocket
frameworks | Tokio | async-runtime | tokio
frameworks | Clap | cli | clap
frameworks | Ruby on Rails | web-app, backend | rails
frameworks | Sinatra | backend | sinatra
frameworks | Laravel | web-app, backend | laravel/framework
frameworks | Symfony | web-app, backend | symfony/framework-bundle
frameworks | ASP.NET Core | backend | microsoft.aspnetcore*
frameworks | Blazor | frontend | microsoft.aspnetcore.components*
# ---- notable libraries (capabilities are the point here) ----------------------------
libraries | Tailwind CSS | styling | tailwindcss
libraries | shadcn/ui | ui-components | @radix-ui/*, class-variance-authority
libraries | Material UI | ui-components | @mui/material
libraries | Chakra UI | ui-components | @chakra-ui/react
libraries | Ant Design | ui-components | antd
libraries | Bootstrap | ui-components | bootstrap, react-bootstrap
libraries | Storybook | design-system, ui-components | storybook, @storybook/*
libraries | Redux | state-management | redux, @reduxjs/toolkit
libraries | Zustand | state-management | zustand
libraries | TanStack Query | data-fetching | @tanstack/react-query, react-query
libraries | SWR | data-fetching | swr
libraries | Axios | http-client | axios
libraries | Retrofit | http-client | com.squareup.retrofit2:*
libraries | Hilt | dependency-injection | com.google.dagger:hilt*, com.google.dagger.hilt.android*
libraries | React Hook Form | forms | react-hook-form
libraries | Formik | forms | formik
libraries | Zod | validation | zod
libraries | Yup | validation | yup
libraries | Pydantic | validation | pydantic
libraries | Marshmallow | validation, serialization | marshmallow
libraries | i18next | i18n | i18next, react-i18next, next-intl
libraries | Chart.js | charts, data-visualization | chart.js, react-chartjs-2
libraries | Recharts | charts, data-visualization | recharts
libraries | D3 | charts, data-visualization | d3
libraries | ECharts | charts, data-visualization | echarts
libraries | Plotly | charts, data-visualization | plotly, plotly.js, react-plotly.js
libraries | Matplotlib | charts, data-visualization | matplotlib
libraries | Leaflet | maps | leaflet, react-leaflet
libraries | Mapbox | maps | mapbox-gl
libraries | Google Maps | maps | @googlemaps/*, @react-google-maps/api, googlemaps
libraries | Stripe | payments | stripe, @stripe/stripe-js, @stripe/react-stripe-js, com.stripe:*, github.com/stripe/stripe-go*
libraries | PayPal | payments | @paypal/*, paypalrestsdk
libraries | Braintree | payments | braintree
libraries | Plaid | banking, fintech | plaid, plaid-python, react-plaid-link
libraries | Twilio | sms, notifications | twilio
libraries | SendGrid | email | @sendgrid/mail, sendgrid
libraries | Nodemailer | email | nodemailer
libraries | Resend | email | resend
libraries | Postmark | email | postmark
libraries | Mailgun | email | mailgun.js, mailgun
libraries | React Email | email, email-templates | @react-email/components, react-email
libraries | Firebase Cloud Messaging | push-notifications | firebase-admin
libraries | PDFKit | pdf | pdfkit
libraries | jsPDF | pdf | jspdf
libraries | pdf-lib | pdf | pdf-lib
libraries | React PDF | pdf | @react-pdf/renderer, react-pdf
libraries | ReportLab | pdf | reportlab
libraries | WeasyPrint | pdf | weasyprint
libraries | PyPDF | pdf, document-parsing | pypdf, pypdf2, pdfplumber, pymupdf
libraries | python-docx | document-generation | python-docx, docx
libraries | openpyxl | spreadsheets | openpyxl, xlsx, exceljs
libraries | Pandas | data-analysis | pandas
libraries | Polars | data-analysis | polars
libraries | NumPy | numerical | numpy
libraries | Apache Spark | big-data, etl | pyspark, org.apache.spark:*
libraries | dbt | etl, data-modeling | dbt-core, dbt-*
libraries | Airflow | etl, orchestration | apache-airflow
libraries | Prefect | etl, orchestration | prefect
libraries | Dagster | etl, orchestration | dagster
libraries | Puppeteer | browser-automation, scraping | puppeteer, puppeteer-core
libraries | Playwright | browser-automation | playwright
libraries | Selenium | browser-automation | selenium
libraries | BeautifulSoup | scraping | beautifulsoup4, bs4
libraries | Scrapy | scraping | scrapy
libraries | Cheerio | scraping | cheerio
libraries | Sharp | image-processing | sharp
libraries | Pillow | image-processing | pillow
libraries | OpenCV | computer-vision, image-processing | opencv-python, opencv-python-headless
libraries | FFmpeg | video-processing | fluent-ffmpeg, ffmpeg-python
libraries | Multer | file-upload | multer
libraries | Uppy | file-upload | @uppy/core
libraries | date-fns | dates | date-fns
libraries | Day.js | dates | dayjs
libraries | Luxon | dates | luxon
libraries | Lodash | utilities | lodash
libraries | RxJS | reactive | rxjs
libraries | Feature flags (LaunchDarkly) | feature-flags | launchdarkly-*, @launchdarkly/*
libraries | Feature flags (Unleash) | feature-flags | unleash-client, @unleash/*
libraries | Feature flags (GrowthBook) | feature-flags, experimentation | @growthbook/*, growthbook
libraries | Segment | analytics | @segment/*, analytics-node
libraries | PostHog | analytics, experimentation | posthog-js, posthog-node, posthog
libraries | Mixpanel | analytics | mixpanel, mixpanel-browser
libraries | Google Analytics | analytics | react-ga4, @next/third-parties
libraries | FHIR | healthcare, interoperability | fhir, fhir.resources, fhirclient, @types/fhir, ca.uhn.hapi.fhir:*, fhir-kit-client
libraries | HL7 | healthcare, interoperability | hl7, hl7apy, python-hl7, node-hl7-client, simple-hl7
libraries | DICOM | healthcare, medical-imaging | pydicom, dcmjs, cornerstone-core
libraries | Algolia search | search | algoliasearch, react-instantsearch
libraries | Meilisearch | search | meilisearch
libraries | Typesense | search | typesense
libraries | Fuse.js | search, client-side-search | fuse.js
libraries | Lunr / MiniSearch | search, client-side-search | lunr, minisearch, flexsearch
libraries | Cron scheduling | scheduling | node-cron, cron, croniter, apscheduler, github.com/robfig/cron*
libraries | Rate limiting | rate-limiting | express-rate-limit, slowapi, rate-limiter-flexible
libraries | Caching | caching | cachetools, lru-cache, node-cache, keyv
libraries | CSV parsing | csv | papaparse, csv-parse, fast-csv
libraries | Markdown rendering | markdown | marked, markdown-it, remark, react-markdown, mistune, markdown
libraries | Rich text editing | rich-text-editor | @tiptap/*, slate, quill, draft-js, lexical, @lexical/*
libraries | Drag and drop | drag-and-drop | @dnd-kit/*, react-dnd, react-beautiful-dnd
libraries | Web3 | blockchain | ethers, web3, viem, wagmi
# ---- testing ---------------------------------------------------------------------------
testing | Jest | unit-testing | jest
testing | Vitest | unit-testing | vitest
testing | Mocha | unit-testing | mocha
testing | Jasmine | unit-testing | jasmine, jasmine-core
testing | AVA | unit-testing | ava
testing | Testing Library | ui-testing | @testing-library/*
testing | Cypress | e2e-testing | cypress
testing | Playwright Test | e2e-testing | @playwright/test
testing | WebdriverIO | e2e-testing | webdriverio, @wdio/*
testing | MSW | api-mocking | msw
testing | Supertest | api-testing | supertest
testing | pytest | unit-testing | pytest
testing | Hypothesis | property-testing | hypothesis
testing | Factory Boy | test-fixtures | factory-boy
testing | tox | test-automation | tox
testing | nox | test-automation | nox
testing | coverage.py | coverage | coverage, pytest-cov
testing | JUnit | unit-testing | junit:junit, org.junit.jupiter:*, org.springframework.boot:spring-boot-starter-test
testing | Mockito | mocking | org.mockito:*
testing | Testcontainers | integration-testing | org.testcontainers:*, testcontainers, github.com/testcontainers/*
testing | testify | unit-testing | github.com/stretchr/testify
testing | RSpec | unit-testing | rspec, rspec-rails
testing | PHPUnit | unit-testing | phpunit/phpunit
testing | xUnit | unit-testing | xunit, xunit.v3*, xunit.core, xunit.runner*
testing | NUnit | unit-testing | nunit, nunit3testadapter, nunit.*
testing | MSTest | unit-testing | mstest, mstest.*, microsoft.visualstudio.testplatform*
testing | Pest | unit-testing | pestphp/pest
testing | k6 | load-testing | k6
testing | Locust | load-testing | locust
# ---- linting / formatting / typing ----------------------------------------------------
linting | ESLint | | eslint
linting | Prettier | | prettier
linting | Biome | | @biomejs/biome
linting | TypeScript | | typescript
linting | Stylelint | | stylelint
linting | Ruff | | ruff
linting | Black | | black
linting | isort | | isort
linting | Flake8 | | flake8
linting | Pylint | | pylint
linting | mypy | | mypy
linting | Pyright | | pyright
linting | pre-commit | | pre-commit
linting | Husky | | husky
linting | lint-staged | | lint-staged
linting | commitlint | | @commitlint/cli
linting | RuboCop | | rubocop
linting | Checkstyle | | com.puppycrawl.tools:checkstyle, org.apache.maven.plugins:maven-checkstyle-plugin
linting | Spring Java Format | | io.spring.javaformat:*
linting | Laravel Pint | | laravel/pint
linting | PHP-CS-Fixer | | friendsofphp/php-cs-fixer
linting | Spotless | | com.diffplug.spotless:*
# ---- build tools ------------------------------------------------------------------------
build_tools | Vite | | vite
build_tools | Webpack | | webpack
build_tools | Rollup | | rollup
build_tools | esbuild | | esbuild
build_tools | Turbopack | | @vercel/turbopack
build_tools | tsup | | tsup
build_tools | SWC | | @swc/core
build_tools | Babel | | @babel/core
build_tools | Parcel | | parcel
build_tools | Turborepo | monorepo | turbo
build_tools | Nx | monorepo | nx
build_tools | Lerna | monorepo | lerna
build_tools | Changesets | release-automation | @changesets/cli
build_tools | semantic-release | release-automation | semantic-release
build_tools | Hatch | | hatchling, hatch
build_tools | Poetry | | poetry-core, poetry
build_tools | setuptools | | setuptools
build_tools | Maturin | | maturin
# ---- databases / storage ---------------------------------------------------------------
databases | PostgreSQL | sql-database | pg, postgres, psycopg, psycopg2, psycopg2-binary, asyncpg, github.com/lib/pq, github.com/jackc/pgx*, org.postgresql:postgresql, npgsql*, aspire.npgsql*, @prisma/adapter-pg
databases | MySQL | sql-database | mysql, mysql2, pymysql, mysqlclient, github.com/go-sql-driver/mysql, com.mysql:*, mysql:mysql-connector-java
databases | SQLite | sql-database, embedded-database | sqlite3, better-sqlite3, sqlite, aiosqlite, github.com/mattn/go-sqlite3
databases | SQL Server | sql-database | mssql, tedious, pyodbc, pymssql, microsoft.data.sqlclient
databases | Oracle | sql-database | oracledb, cx-oracle
databases | MongoDB | document-database | mongodb, mongoose, pymongo, motor, go.mongodb.org/mongo-driver*, org.mongodb:*
databases | Redis | caching, key-value | redis, ioredis, redis-py, aioredis, github.com/redis/go-redis*, github.com/go-redis/redis*, stackexchange.redis
databases | DynamoDB | nosql | @aws-sdk/client-dynamodb, @aws-sdk/lib-dynamodb, pynamodb, dynamoose
databases | Cassandra | nosql | cassandra-driver
databases | Elasticsearch | search, search-engine | @elastic/elasticsearch, elasticsearch, elasticsearch-dsl
databases | OpenSearch | search, search-engine | @opensearch-project/opensearch, opensearch-py
databases | Neo4j | graph-database | neo4j, neo4j-driver
databases | Firestore | document-database | @google-cloud/firestore, google-cloud-firestore, firebase
databases | Supabase | backend-as-a-service, sql-database | @supabase/supabase-js, supabase
databases | Snowflake | data-warehouse | snowflake-connector-python, snowflake-sdk, snowflake-sqlalchemy, snowflake-snowpark-python, dbt-snowflake, apache-airflow-providers-snowflake, net.snowflake:*
databases | BigQuery | data-warehouse | google-cloud-bigquery, @google-cloud/bigquery
databases | DuckDB | analytics-database | duckdb, @duckdb/*
databases | ClickHouse | analytics-database | clickhouse-connect, @clickhouse/client
databases | Prisma | orm | prisma, @prisma/client
databases | Drizzle | orm | drizzle-orm
databases | TypeORM | orm | typeorm
databases | Sequelize | orm | sequelize
databases | Knex | query-builder | knex
databases | Kysely | query-builder | kysely
databases | SQLAlchemy | orm | sqlalchemy
databases | SQLModel | orm | sqlmodel
databases | Alembic | db-migrations | alembic
databases | Django ORM migrations | db-migrations | django
databases | Flyway | db-migrations | org.flywaydb:*
databases | Liquibase | db-migrations | org.liquibase:*
databases | Hibernate | orm | org.hibernate*:*
databases | Room | orm, embedded-database | androidx.room:*
databases | GORM | orm | gorm.io/gorm
databases | Entity Framework | orm | microsoft.entityframeworkcore*
databases | ActiveRecord | orm | activerecord
databases | S3 storage | file-storage | @aws-sdk/client-s3, aws-sdk-s3, s3fs, minio
databases | Google Cloud Storage | file-storage | @google-cloud/storage, google-cloud-storage
databases | Azure Blob Storage | file-storage | @azure/storage-blob, azure-storage-blob
# ---- messaging ---------------------------------------------------------------------------
messaging | Kafka | event-streaming | kafkajs, kafka-python, confluent-kafka, org.apache.kafka:*, org.springframework.kafka:*, confluent.kafka, github.com/segmentio/kafka-go, github.com/confluentinc/confluent-kafka-go*
messaging | RabbitMQ | queue | amqplib, pika, aio-pika, github.com/rabbitmq/amqp091-go, com.rabbitmq:*, rabbitmq.client, masstransit.rabbitmq, aspire.rabbitmq*, org.springframework.boot:spring-boot-starter-amqp
messaging | SQS | queue | @aws-sdk/client-sqs
messaging | SNS | pub-sub, notifications | @aws-sdk/client-sns
messaging | Google Pub/Sub | pub-sub | @google-cloud/pubsub, google-cloud-pubsub
messaging | Azure Service Bus | queue | @azure/service-bus, azure-servicebus
messaging | NATS | pub-sub | nats, nats-py, github.com/nats-io/nats.go
messaging | BullMQ | queue, background-jobs | bullmq, bull
messaging | RQ | queue, background-jobs | rq
messaging | Sidekiq | background-jobs | sidekiq
messaging | Temporal | workflow-orchestration | @temporalio/*, temporalio, go.temporal.io/sdk
messaging | Inngest | background-jobs, workflow-orchestration | inngest
# ---- cloud ------------------------------------------------------------------------------
cloud | AWS | | aws-sdk, @aws-sdk/*, boto3, botocore, aioboto3, github.com/aws/aws-sdk-go*, software.amazon.awssdk:*, com.amazonaws:*, awssdk.*, hashicorp/aws, terraform-aws-modules/*
cloud | AWS Lambda | serverless | aws-lambda, @types/aws-lambda, aws-lambda-powertools, mangum, github.com/aws/aws-lambda-go
cloud | AWS CDK | infrastructure-as-code | aws-cdk-lib, aws-cdk, constructs
cloud | Google Cloud | | @google-cloud/*, google-cloud-*, cloud.google.com/go*, com.google.cloud:*, hashicorp/google, hashicorp/google-beta, terraform-google-modules/*
cloud | Firebase | backend-as-a-service | firebase, firebase-admin, firebase-functions, com.google.firebase:*
cloud | Azure | | @azure/*, azure-*, github.com/azure/azure-sdk-for-go*, com.azure:*, hashicorp/azurerm, hashicorp/azuread, azure/azapi
infrastructure | .NET Aspire | cloud-native | aspire.*
cloud | Vercel | | @vercel/*, vercel
cloud | Cloudflare | edge | wrangler, @cloudflare/*
cloud | Pulumi | infrastructure-as-code | @pulumi/*, pulumi, pulumi-*
cloud | Serverless Framework | serverless | serverless
# ---- observability ----------------------------------------------------------------------
observability | OpenTelemetry | tracing | @opentelemetry/*, opentelemetry-*, go.opentelemetry.io/*, io.opentelemetry:*, opentelemetry, opentelemetry.*
observability | Sentry | error-tracking | @sentry/*, sentry-sdk, github.com/getsentry/sentry-go, io.sentry:*
observability | Datadog | monitoring | dd-trace, ddtrace, datadog, @datadog/*
observability | New Relic | monitoring | newrelic
observability | Prometheus | metrics | prom-client, prometheus-client, prometheus_client, github.com/prometheus/client_golang, io.micrometer:*
observability | Winston | logging | winston
observability | Pino | logging | pino
observability | structlog | logging | structlog
observability | Loguru | logging | loguru
observability | Zap | logging | go.uber.org/zap
observability | Logrus | logging | github.com/sirupsen/logrus
observability | Serilog | logging | serilog, serilog.*
# ---- auth ------------------------------------------------------------------------------
auth | Auth.js / NextAuth | authentication | next-auth, @auth/*
auth | Clerk | authentication | @clerk/*
auth | Auth0 | authentication | auth0, @auth0/*, auth0-python
auth | Okta | authentication, sso | @okta/*, okta
auth | Azure AD / MSAL | authentication, sso | @azure/msal-browser, @azure/msal-node, @azure/msal-react, msal
auth | Firebase Auth | authentication | firebase-admin
auth | Supabase Auth | authentication | @supabase/auth-helpers-nextjs, @supabase/ssr
auth | Passport | authentication | passport, passport-*
auth | Lucia | authentication | lucia
auth | Keycloak | authentication, sso | keycloak-js, python-keycloak
auth | JWT | authentication, tokens | jsonwebtoken, jose, pyjwt, python-jose, github.com/golang-jwt/jwt*, io.jsonwebtoken:*
auth | OAuth client | oauth | authlib, oauthlib, requests-oauthlib, simple-oauth2, golang.org/x/oauth2
auth | Spring Security | authentication | org.springframework.security:*, org.springframework.boot:spring-boot-starter-security
auth | Django allauth | authentication | django-allauth
auth | bcrypt / argon2 | password-hashing | bcrypt, bcryptjs, argon2, argon2-cffi, passlib
auth | SAML | sso | python3-saml, @node-saml/*, passport-saml, samlify
auth | Casbin / RBAC | authorization | casbin, pycasbin, github.com/casbin/casbin*
# ---- AI / ML ---------------------------------------------------------------------------
ai | Anthropic SDK | llm | anthropic, @anthropic-ai/sdk, github.com/anthropics/anthropic-sdk-go, com.anthropic:*, anthropic-sdk-*
ai | Claude Agent SDK | llm, ai-agents | claude-agent-sdk, @anthropic-ai/claude-agent-sdk, claude-code-sdk, @anthropic-ai/claude-code
ai | OpenAI SDK | llm | openai, github.com/openai/openai-go, github.com/sashabaranov/go-openai, com.openai:*, async-openai
ai | OpenAI Agents SDK | llm, ai-agents | openai-agents, @openai/agents
ai | Azure OpenAI | llm | @azure/openai, azure-ai-openai, azure.ai.openai
ai | Google Gen AI | llm | google-genai, google-generativeai, @google/genai, @google/generative-ai
ai | Vertex AI | llm, ml-platform | google-cloud-aiplatform, vertexai, @google-cloud/vertexai
ai | Google ADK | llm, ai-agents | google-adk
ai | Amazon Bedrock | llm | @aws-sdk/client-bedrock-runtime, @aws-sdk/client-bedrock-agent-runtime, langchain-aws
ai | Mistral | llm | mistralai, @mistralai/mistralai
ai | Cohere | llm, embeddings | cohere, cohere-ai
ai | Groq | llm | groq, groq-sdk
ai | Together AI | llm | together, together-ai
ai | Ollama | llm, local-llm | ollama
ai | LiteLLM | llm, llm-gateway | litellm
ai | Vercel AI SDK | llm | ai, @ai-sdk/*
ai | LangChain | llm, llm-orchestration | langchain, langchain-*, @langchain/*
ai | LangGraph | llm, ai-agents | langgraph, @langchain/langgraph
ai | LlamaIndex | llm, rag | llama-index, llama-index-*, llamaindex
ai | CrewAI | llm, ai-agents | crewai, crewai-tools
ai | AutoGen | llm, ai-agents | autogen, pyautogen, autogen-agentchat, autogen-core
ai | Semantic Kernel | llm, ai-agents | semantic-kernel, microsoft.semantickernel*
ai | PydanticAI | llm, ai-agents | pydantic-ai, pydantic-ai-slim
ai | smolagents | llm, ai-agents | smolagents
ai | Mastra | llm, ai-agents | @mastra/core, mastra
ai | Haystack | llm, rag | haystack-ai, farm-haystack
ai | DSPy | llm, prompt-optimization | dspy, dspy-ai
ai | Instructor | llm, structured-output | instructor
ai | Guidance / Outlines | llm, structured-output | guidance, outlines
ai | Spring AI | llm | org.springframework.ai:*
ai | LangChain4j | llm | dev.langchain4j:*
ai | Model Context Protocol | mcp, ai-tools | mcp, fastmcp, @modelcontextprotocol/sdk, github.com/mark3labs/mcp-go, github.com/modelcontextprotocol/go-sdk, io.modelcontextprotocol*:*, modelcontextprotocol*
ai | Hugging Face Transformers | ml, nlp | transformers, @huggingface/transformers, @xenova/transformers
ai | Hugging Face Hub | ml | huggingface-hub, @huggingface/inference
ai | Sentence Transformers | embeddings | sentence-transformers
ai | PyTorch | ml, deep-learning | torch, torchvision, pytorch-lightning, lightning
ai | TensorFlow | ml, deep-learning | tensorflow, tensorflow-cpu, @tensorflow/tfjs
ai | JAX | ml, deep-learning | jax, flax
ai | scikit-learn | ml | scikit-learn, sklearn
ai | XGBoost / LightGBM | ml | xgboost, lightgbm, catboost
ai | spaCy / NLTK | nlp | spacy, nltk
ai | MLflow | ml-ops | mlflow
ai | Weights & Biases | ml-ops | wandb
ai | Pinecone | vector-search, rag | pinecone, pinecone-client, @pinecone-database/pinecone
ai | Chroma | vector-search, rag | chromadb
ai | Weaviate | vector-search, rag | weaviate-client, weaviate-ts-client
ai | Qdrant | vector-search, rag | qdrant-client, @qdrant/js-client-rest
ai | pgvector | vector-search, rag | pgvector
ai | FAISS | vector-search | faiss-cpu, faiss-gpu
ai | LanceDB | vector-search | lancedb, @lancedb/lancedb
ai | Langfuse | llm-observability | langfuse
ai | LangSmith | llm-observability | langsmith
ai | Arize Phoenix | llm-observability | arize-phoenix, openinference-*
ai | Helicone | llm-observability | helicone, @helicone/*
ai | promptfoo | llm-evals | promptfoo
ai | DeepEval | llm-evals | deepeval
ai | Ragas | llm-evals | ragas
ai | Braintrust | llm-evals | braintrust
ai | Inspect | llm-evals | inspect-ai
ai | tiktoken | tokenization | tiktoken, js-tiktoken
ai | Unstructured | document-parsing, rag | unstructured
ai | Docling | document-parsing, rag | docling
"""

# Files and directory markers. Format: category | Label | capabilities | glob, glob
_FILE_TABLE = """
infrastructure | Docker | containers | **/Dockerfile, **/Dockerfile.*, **/*.dockerfile, **/Containerfile
infrastructure | Docker Compose | containers | **/docker-compose*.yml, **/docker-compose*.yaml, **/compose.yml, **/compose.yaml
infrastructure | Dev Containers | dev-environment | .devcontainer/**, .devcontainer.json
infrastructure | Terraform | infrastructure-as-code | **/*.tf
infrastructure | Terragrunt | infrastructure-as-code | **/terragrunt.hcl
infrastructure | Helm | kubernetes | **/Chart.yaml
infrastructure | Kustomize | kubernetes | **/kustomization.yaml, **/kustomization.yml
infrastructure | Skaffold | kubernetes | skaffold.yaml
infrastructure | Pulumi | infrastructure-as-code | **/Pulumi.yaml
infrastructure | AWS CDK | infrastructure-as-code | **/cdk.json
infrastructure | AWS SAM / CloudFormation | infrastructure-as-code, serverless | template.yaml, template.yml, **/samconfig.toml
infrastructure | Serverless Framework | serverless | **/serverless.yml, **/serverless.yaml, **/serverless.ts
infrastructure | Ansible | configuration-management | **/ansible.cfg, **/playbook*.yml, **/playbooks/**
infrastructure | Bicep | infrastructure-as-code | **/*.bicep
infrastructure | Nix | dev-environment | flake.nix, shell.nix, default.nix
infrastructure | Bazel | | WORKSPACE, WORKSPACE.bazel, MODULE.bazel, **/BUILD.bazel
infrastructure | Make | | Makefile, **/Makefile
infrastructure | Just | | justfile, Justfile
infrastructure | Taskfile | | Taskfile.yml, Taskfile.yaml
cloud | Vercel | | vercel.json
cloud | Netlify | | netlify.toml
cloud | Fly.io | | fly.toml
cloud | Render | | render.yaml
cloud | Heroku | | Procfile, app.json
cloud | Google App Engine | | app.yaml
cloud | Firebase | backend-as-a-service | firebase.json, .firebaserc
cloud | AWS Amplify | | amplify.yml, amplify/**
cloud | Cloudflare Workers | edge | wrangler.toml, wrangler.json, wrangler.jsonc
cloud | Azure Static Web Apps | | staticwebapp.config.json
cloud | Railway | | railway.json, railway.toml
ci_cd | GitHub Actions | | .github/workflows/*.yml, .github/workflows/*.yaml
ci_cd | GitLab CI | | .gitlab-ci.yml
ci_cd | Jenkins | | Jenkinsfile, **/Jenkinsfile
ci_cd | CircleCI | | .circleci/config.yml
ci_cd | Azure Pipelines | | azure-pipelines.yml, **/azure-pipelines*.yml
ci_cd | Bitbucket Pipelines | | bitbucket-pipelines.yml
ci_cd | Travis CI | | .travis.yml
ci_cd | Buildkite | | .buildkite/**
ci_cd | Argo CD | gitops | **/argocd/**, **/*application*.argocd.yaml
ci_cd | Dependabot | dependency-updates | .github/dependabot.yml, .github/dependabot.yaml
ci_cd | Renovate | dependency-updates | renovate.json, renovate.json5, .renovaterc, .renovaterc.json, .github/renovate.json, .github/renovate.json5
ci_cd | release-please | release-automation | release-please-config.json, .release-please-manifest.json
ci_cd | GoReleaser | release-automation | .goreleaser.yml, .goreleaser.yaml
linting | ESLint | | **/.eslintrc, **/.eslintrc.*, **/eslint.config.*
linting | Prettier | | **/.prettierrc, **/.prettierrc.*, **/prettier.config.*
linting | Biome | | biome.json, biome.jsonc
linting | Ruff | | ruff.toml, .ruff.toml
linting | Flake8 | | .flake8
linting | mypy | | mypy.ini, .mypy.ini
linting | Pyright | | pyrightconfig.json
linting | golangci-lint | | .golangci.yml, .golangci.yaml, .golangci.toml
linting | RuboCop | | .rubocop.yml
linting | rustfmt | | rustfmt.toml, .rustfmt.toml, **/rustfmt.toml
linting | Clippy | | clippy.toml, .clippy.toml
linting | Checkstyle | | **/checkstyle*.xml
linting | Laravel Pint | | pint.json
linting | Stylelint | | .stylelintrc, .stylelintrc.*, stylelint.config.*
linting | EditorConfig | | .editorconfig
linting | pre-commit | | .pre-commit-config.yaml
linting | Husky | | .husky/**
linting | markdownlint | | .markdownlint*
linting | SonarQube | code-quality | sonar-project.properties
linting | Codecov | coverage | codecov.yml, .codecov.yml
linting | Snyk | security-scanning | .snyk
linting | CodeQL | security-scanning | .github/codeql/**, .github/workflows/codeql*.yml
testing | Jest | unit-testing | **/jest.config.*
testing | Vitest | unit-testing | **/vitest.config.*, **/vitest.workspace.*
testing | Playwright Test | e2e-testing | **/playwright.config.*
testing | Cypress | e2e-testing | **/cypress.config.*, cypress.json
testing | pytest | unit-testing | **/pytest.ini, **/conftest.py
testing | tox | test-automation | tox.ini
testing | Karma | unit-testing | **/karma.conf.js
build_tools | Vite | | **/vite.config.*
build_tools | Webpack | | **/webpack.config.*
build_tools | Turborepo | monorepo | turbo.json
build_tools | Nx | monorepo | nx.json
build_tools | Lerna | monorepo | lerna.json
build_tools | pnpm workspaces | monorepo | pnpm-workspace.yaml
build_tools | Gradle | | **/build.gradle, **/build.gradle.kts
build_tools | Maven | | **/pom.xml
frameworks | Next.js | frontend, ssr, web-app | **/next.config.*
frameworks | Nuxt | frontend, ssr | **/nuxt.config.*
frameworks | Angular | frontend, ui | **/angular.json
frameworks | SvelteKit | frontend, ssr | **/svelte.config.*
frameworks | Astro | frontend, static-site | **/astro.config.*
frameworks | Docusaurus | documentation-site | **/docusaurus.config.*
frameworks | MkDocs | documentation-site | mkdocs.yml
frameworks | Sphinx | documentation-site | docs/conf.py, doc/conf.py, docs/source/conf.py
frameworks | Hugo | static-site | hugo.toml, hugo.yaml
frameworks | Jekyll | static-site | _config.yml, Gemfile.jekyll
frameworks | Storybook | design-system, ui-components | .storybook/**
frameworks | Android | mobile | **/AndroidManifest.xml
libraries | Airflow | etl, orchestration | **/dags/*.py, airflow.cfg
libraries | dbt | etl, data-modeling | **/dbt_project.yml
libraries | Tailwind CSS | styling | **/tailwind.config.*
libraries | OpenAPI | rest-api, api-spec | **/openapi*.yaml, **/openapi*.yml, **/openapi*.json, **/swagger*.yaml, **/swagger*.yml, **/swagger*.json
libraries | GraphQL schema | graphql-api, api-spec | **/*.graphql, **/*.gql
libraries | Protocol Buffers | rpc-api, api-spec | **/*.proto
libraries | AsyncAPI | event-driven, api-spec | **/asyncapi*.yaml, **/asyncapi*.yml
libraries | Prisma schema | orm | **/schema.prisma
libraries | Jupyter notebooks | data-analysis, notebooks | **/*.ipynb
"""


@dataclass(frozen=True)
class Rule:
    category: str
    label: str
    capabilities: tuple[str, ...]


def _parse(table: str) -> list[tuple[Rule, list[str]]]:
    rows: list[tuple[Rule, list[str]]] = []
    for raw in table.strip().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        category, label, caps, patterns = (part.strip() for part in line.split("|"))
        rule = Rule(category, label, tuple(c.strip() for c in caps.split(",") if c.strip()))
        rows.append((rule, [p.strip() for p in patterns.split(",") if p.strip()]))
    return rows


def normalize_dep(name: str) -> str:
    return name.strip().lower().replace("_", "-")


_EXACT: dict[str, list[Rule]] = {}
_PREFIX: list[tuple[str, Rule]] = []
for _rule, _patterns in _parse(_DEPENDENCY_TABLE):
    for _p in _patterns:
        _norm = normalize_dep(_p)
        if _norm.endswith("*"):
            _PREFIX.append((_norm[:-1], _rule))
        else:
            _EXACT.setdefault(_norm, []).append(_rule)

FILE_RULES: list[tuple[Rule, list[str]]] = _parse(_FILE_TABLE)


def match_dependency(name: str) -> list[Rule]:
    norm = normalize_dep(name)
    hits = list(_EXACT.get(norm, []))
    hits.extend(rule for prefix, rule in _PREFIX if norm.startswith(prefix))
    return hits
