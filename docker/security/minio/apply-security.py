from pathlib import Path
p=Path('/src/minio/cmd/generic-handlers.go')
s=p.read_text()
marker='func setRequestValidityMiddleware(h http.Handler) http.Handler {\n\treturn http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {'
assert s.count(marker)==1, 'Upstream request middleware changed'
s=s.replace(marker,marker+'\n\t\tif rejectUnsafeLegacyS3Features(r) {\n\t\t\twriteErrorResponse(r.Context(), w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)\n\t\t\treturn\n\t\t}')
p.write_text(s)
