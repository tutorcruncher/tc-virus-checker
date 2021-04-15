web: uvicorn tc_av.app.main:tc_av_app --host=0.0.0.0 --port=${PORT:-8000}
worker: bin/start-clamd bundle exec sidekiq
