# KumoKeep mobile app (Flutter)

Not scaffolded yet: Flutter isn't installed on the dev machine. Once it is:

```bash
cd mobile
flutter create --org com.kumokeep --project-name kumokeep --platforms android,ios .
```

Planned scope (see `docs/ARCHITECTURE.md`):

- Photo auto-upload (`photo_manager` + `workmanager`, tus uploads) and timeline
- Notes, offline-first
- File browser

Passwords are handled by the official Bitwarden apps pointed at `https://<host>/vault`.
