// Copyright 2023-2025 The Sigstore Authors, Red Hat Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1alpha1

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/google/go-containerregistry/pkg/v1/remote"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
)

type GKMCacheWebhook struct{}

type nonExpiringVerifier struct {
	signature.Verifier
}

var (
	gkmcachelog = logf.Log.WithName("gkmcache-resource")
)

// SetupWebhookWithManager sets up the webhook with the controller-runtime manager
func (w *GKMCache) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(&GKMCache{}).
		WithDefaulter(w, admission.DefaulterRemoveUnknownOrOmitableFields).
		WithValidator(w).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// +kubebuilder:webhook:path=/mutate-gkm-io-v1alpha1-gkmcache,mutating=true,failurePolicy=fail,sideEffects=None,groups=gkm.io,resources=gkmcaches,verbs=create;update,versions=v1alpha1,name=mgkmcache.kb.io,admissionReviewVersions=v1

var _ webhook.CustomDefaulter = &GKMCache{}
var _ webhook.CustomValidator = &GKMCache{}

// Default implements the defaulting logic (mutating webhook)
func (w *GKMCache) Default(ctx context.Context, obj runtime.Object) error {
	log := logf.FromContext(ctx)
	log.Info("Webhook called", "object", obj)

	cache, ok := obj.(*GKMCache)
	if !ok {
		return apierrors.NewBadRequest(fmt.Sprintf("expected GKMCache, got %T", obj))
	}
	log.Info("Decoded GKMCache object", "name", cache.Name, "namespace", cache.Namespace)

	if cache.Annotations == nil {
		cache.Annotations = map[string]string{}
	}

	if _, exists := cache.Annotations["gkm.io/resolvedDigest"]; exists {
		gkmcachelog.Info("resolvedDigest already set, skipping")
		return nil
	}

	if cache.Spec.Image == "" {
		gkmcachelog.Info("spec.image is empty, skipping")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log.Info("Verifying image signature", "image", cache.Spec.Image)

	digest, err := verifyImageSignature(ctx, cache.Spec.Image)
	if err != nil {
		gkmcachelog.Error(err, "failed to verify image or resolve digest")
		return err
	}
	log.Info("Resolved image digest", "digest", digest)

	cache.Annotations["gkm.io/resolvedDigest"] = digest
	gkmcachelog.Info("added resolvedDigest", "digest", digest)
	return nil
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-gkm-io-v1alpha1-gkmcache,mutating=false,failurePolicy=fail,sideEffects=None,groups=gkm.io,resources=gkmcaches,verbs=create;update,versions=v1alpha1,name=vgkmcache.kb.io,admissionReviewVersions=v1

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (w *GKMCache) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	cache, ok := obj.(*GKMCache)
	if !ok {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("expected GKMCache, got %T", obj))
	}

	if cache.Spec.Image == "" {
		return nil, fmt.Errorf("spec.image must be set")
	}

	if _, exists := cache.Annotations["gkm.io/resolvedDigest"]; exists {
		return nil, fmt.Errorf("users may not set gkm.io/resolvedDigest directly")
	}

	return nil, nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (w *GKMCache) ValidateUpdate(_ context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	oldCache, ok1 := oldObj.(*GKMCache)
	newCache, ok2 := newObj.(*GKMCache)
	if !ok1 || !ok2 {
		return nil, apierrors.NewBadRequest("type assertion to GKMCache failed")
	}

	oldDigest := oldCache.Annotations["gkm.io/resolvedDigest"]
	newDigest := newCache.Annotations["gkm.io/resolvedDigest"]

	if oldDigest != newDigest {
		return nil, fmt.Errorf("modification of gkm.io/resolvedDigest is not allowed")
	}

	return nil, nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (w *GKMCache) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

// Verifies a public image has a valid cosign signature
// verifyImageSignature verifies the signature on an imageRef and returns its digest if valid.
func verifyImageSignature(ctx context.Context, imageRef string) (string, error) {
	// Step 1: Build a bundle from the OCI image (including Rekor + TSA data if available)
	bndl, digestHex, err := bundleFromOCIImage(imageRef, true, true)
	if err != nil {
		return "", fmt.Errorf("failed to extract bundle from OCI image: %w", err)
	}

	// Step 2: Decode digest string into bytes
	digestBytes, err := hex.DecodeString(*digestHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode digest hex: %w", err)
	}

	// Step 3: Load trusted roots from TUF
	tufClient, err := tuf.New(tuf.DefaultOptions())
	if err != nil {
		return "", fmt.Errorf("failed to initialize TUF: %w", err)
	}
	trustedMaterial, err := root.GetTrustedRoot(tufClient)
	if err != nil {
		return "", fmt.Errorf("failed to fetch trusted root: %w", err)
	}

	// Step 4: Build verifier
	verifier, err := verify.NewVerifier(trustedMaterial,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create verifier: %w", err)
	}

	// Step 5: Build identity policy (optional; configure or disable if needed)
	certID, err := verify.NewShortCertificateIdentity(
		"https://token.actions.githubusercontent.com", "", "", "",
	)
	if err != nil {
		return "", fmt.Errorf("failed to construct cert identity: %w", err)
	}

	policy := verify.NewPolicy(
		verify.WithArtifactDigest("sha256", digestBytes),
		verify.WithCertificateIdentity(certID),
	)

	// Step 6: Verify the signature
	if _, err := verifier.Verify(bndl, policy); err != nil {
		return "", fmt.Errorf("image signature verification failed: %w", err)
	}

	return *digestHex, nil
}

// bundleFromOCIImage returns a Bundle based on OCI image reference.
func bundleFromOCIImage(imageRef string, hasTlog, hasTimestamp bool) (*bundle.Bundle, *string, error) {
	// 1. Get the simple signing layer
	simpleSigning, err := simpleSigningLayerFromOCIImage(imageRef)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting simple signing layer: %w", err)
	}
	// 2. Build the verification material for the bundle
	verificationMaterial, err := getBundleVerificationMaterial(simpleSigning, hasTlog, hasTimestamp)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting verification material: %w", err)
	}
	// 3. Build the message signature for the bundle
	msgSignature, err := getBundleMsgSignature(simpleSigning)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting message signature: %w", err)
	}
	// 4. Construct and verify the bundle
	bundleMediaType, err := bundle.MediaTypeString("0.1")
	if err != nil {
		return nil, nil, fmt.Errorf("error getting bundle media type: %w", err)
	}
	pb := protobundle.Bundle{
		MediaType:            bundleMediaType,
		VerificationMaterial: verificationMaterial,
		Content:              msgSignature,
	}
	bun, err := bundle.NewBundle(&pb)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating bundle: %w", err)
	}
	// 5. Return the bundle and the digest of the simple signing layer (this is what is signed)
	return bun, &simpleSigning.Digest.Hex, nil
}

// simpleSigningLayerFromOCIImage returns the simple signing layer from the OCI image reference
func simpleSigningLayerFromOCIImage(imageRef string) (*v1.Descriptor, error) {
	// 1. Get the image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("error parsing image reference: %w", err)
	}
	// 2. Get the image descriptor
	desc, err := remote.Get(ref)
	if err != nil {
		return nil, fmt.Errorf("error getting image descriptor: %w", err)
	}
	// 3. Get the digest
	digest := ref.Context().Digest(desc.Digest.String())
	h, err := v1.NewHash(digest.Identifier())
	if err != nil {
		return nil, fmt.Errorf("error getting hash: %w", err)
	}
	// 4. Construct the signature reference - sha256-<hash>.sig
	sigTag := digest.Context().Tag(fmt.Sprint(h.Algorithm, "-", h.Hex, ".sig"))
	// 5. Get the manifest of the signature
	mf, err := crane.Manifest(sigTag.Name())
	if err != nil {
		return nil, fmt.Errorf("error getting signature manifest: %w", err)
	}
	sigManifest, err := v1.ParseManifest(bytes.NewReader(mf))
	if err != nil {
		return nil, fmt.Errorf("error parsing signature manifest: %w", err)
	}
	// 6. Ensure there is at least one layer and it is a simple signing layer
	if len(sigManifest.Layers) == 0 || sigManifest.Layers[0].MediaType != "application/vnd.dev.cosign.simplesigning.v1+json" {
		return nil, fmt.Errorf("no suitable layers found in signature manifest")
	}
	// 7. Return the layer - most probably there are more layers (one for each signature) but verifying one is enough
	return &sigManifest.Layers[0], nil
}

// getBundleVerificationMaterial returns the bundle verification material from the simple signing layer
func getBundleVerificationMaterial(manifestLayer *v1.Descriptor, hasTlog, hasTimestamp bool) (*protobundle.VerificationMaterial, error) {
	// 1. Get the signing certificate chain
	signingCert, err := getVerificationMaterialX509CertificateChain(manifestLayer)
	if err != nil {
		return nil, fmt.Errorf("error getting signing certificate: %w", err)
	}
	// 2. Get the transparency log entries
	var tlogEntries []*protorekor.TransparencyLogEntry
	if hasTlog {
		tlogEntries, err = getVerificationMaterialTlogEntries(manifestLayer)
		if err != nil {
			return nil, fmt.Errorf("error getting tlog entries: %w", err)
		}
	}
	var timestampEntries *protobundle.TimestampVerificationData
	if hasTimestamp {
		timestampEntries, err = getVerificationMaterialTimestampEntries(manifestLayer)
		if err != nil {
			return nil, fmt.Errorf("error getting timestamp entries: %w", err)
		}
	}
	// 3. Construct the verification material
	return &protobundle.VerificationMaterial{
		Content:                   signingCert,
		TlogEntries:               tlogEntries,
		TimestampVerificationData: timestampEntries,
	}, nil
}

// getVerificationMaterialTlogEntries returns the verification material transparency log entries from the simple signing layer
func getVerificationMaterialTlogEntries(manifestLayer *v1.Descriptor) ([]*protorekor.TransparencyLogEntry, error) {
	// 1. Get the bundle annotation
	bun := manifestLayer.Annotations["dev.sigstore.cosign/bundle"]
	var jsonData map[string]interface{}
	err := json.Unmarshal([]byte(bun), &jsonData)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling json: %w", err)
	}

	// 2. Get the log index, log ID, integrated time, signed entry timestamp and body
	logIndex, ok := jsonData["Payload"].(map[string]interface{})["logIndex"].(float64)
	if !ok {
		return nil, fmt.Errorf("error getting logIndex")
	}
	li, ok := jsonData["Payload"].(map[string]interface{})["logID"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting logID")
	}
	logID, err := hex.DecodeString(li)
	if err != nil {
		return nil, fmt.Errorf("error decoding logID: %w", err)
	}
	integratedTime, ok := jsonData["Payload"].(map[string]interface{})["integratedTime"].(float64)
	if !ok {
		return nil, fmt.Errorf("error getting integratedTime")
	}
	set, ok := jsonData["SignedEntryTimestamp"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting SignedEntryTimestamp")
	}
	signedEntryTimestamp, err := base64.StdEncoding.DecodeString(set)
	if err != nil {
		return nil, fmt.Errorf("error decoding signedEntryTimestamp: %w", err)
	}
	// 3. Unmarshal the body and extract the rekor KindVersion details
	body, ok := jsonData["Payload"].(map[string]interface{})["body"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting body")
	}
	bodyBytes, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("error decoding body: %w", err)
	}
	err = json.Unmarshal(bodyBytes, &jsonData)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling json: %w", err)
	}
	apiVersion := jsonData["apiVersion"].(string)
	kind := jsonData["kind"].(string)
	// 4. Construct the transparency log entry list
	return []*protorekor.TransparencyLogEntry{
		{
			LogIndex: int64(logIndex),
			LogId: &protocommon.LogId{
				KeyId: logID,
			},
			KindVersion: &protorekor.KindVersion{
				Kind:    kind,
				Version: apiVersion,
			},
			IntegratedTime: int64(integratedTime),
			InclusionPromise: &protorekor.InclusionPromise{
				SignedEntryTimestamp: signedEntryTimestamp,
			},
			InclusionProof:    nil,
			CanonicalizedBody: bodyBytes,
		},
	}, nil
}

func getVerificationMaterialTimestampEntries(manifestLayer *v1.Descriptor) (*protobundle.TimestampVerificationData, error) {
	// 1. Get the bundle annotation
	ts := manifestLayer.Annotations["dev.sigstore.cosign/rfc3161timestamp"]
	// 2. Get the key/value pairs maps
	var keyValPairs map[string]string
	err := json.Unmarshal([]byte(ts), &keyValPairs)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON blob into key/val map: %w", err)
	}
	// 3. Verify the key "SignedRFC3161Timestamp" is present
	if _, ok := keyValPairs["SignedRFC3161Timestamp"]; !ok {
		return nil, errors.New("error getting SignedRFC3161Timestamp from key/value pairs")
	}
	// 4. Decode the base64 encoded timestamp
	der, err := base64.StdEncoding.DecodeString(keyValPairs["SignedRFC3161Timestamp"])
	if err != nil {
		return nil, fmt.Errorf("error decoding base64 encoded timestamp: %w", err)
	}
	// 4. Construct the timestamp entry list
	return &protobundle.TimestampVerificationData{
		Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{
			{
				SignedTimestamp: der,
			},
		},
	}, nil
}

// getVerificationMaterialX509CertificateChain returns the verification material X509 certificate chain from the simple signing layer
func getVerificationMaterialX509CertificateChain(manifestLayer *v1.Descriptor) (*protobundle.VerificationMaterial_X509CertificateChain, error) {
	// 1. Get the PEM certificate from the simple signing layer
	pemCert := manifestLayer.Annotations["dev.sigstore.cosign/certificate"]
	// 2. Construct the DER encoded version of the PEM certificate
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	signingCert := protocommon.X509Certificate{
		RawBytes: block.Bytes,
	}
	// 3. Construct the X509 certificate chain
	return &protobundle.VerificationMaterial_X509CertificateChain{
		X509CertificateChain: &protocommon.X509CertificateChain{
			Certificates: []*protocommon.X509Certificate{&signingCert},
		},
	}, nil
}

// getBundleMsgSignature returns the bundle message signature from the simple signing layer
func getBundleMsgSignature(simpleSigningLayer *v1.Descriptor) (*protobundle.Bundle_MessageSignature, error) {
	// 1. Get the message digest algorithm
	var msgHashAlg protocommon.HashAlgorithm
	switch simpleSigningLayer.Digest.Algorithm {
	case "sha256":
		msgHashAlg = protocommon.HashAlgorithm_SHA2_256
	default:
		return nil, fmt.Errorf("unknown digest algorithm: %s", simpleSigningLayer.Digest.Algorithm)
	}
	// 2. Get the message digest
	digest, err := hex.DecodeString(simpleSigningLayer.Digest.Hex)
	if err != nil {
		return nil, fmt.Errorf("error decoding digest: %w", err)
	}
	// 3. Get the signature
	s := simpleSigningLayer.Annotations["dev.cosignproject.cosign/signature"]
	sig, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("error decoding manSig: %w", err)
	}
	// Construct the bundle message signature
	return &protobundle.Bundle_MessageSignature{
		MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{
				Algorithm: msgHashAlg,
				Digest:    digest,
			},
			Signature: sig,
		},
	}, nil
}

func (*nonExpiringVerifier) ValidAtTime(_ time.Time) bool {
	return true
}

func trustedPublicKeyMaterial(pk crypto.PublicKey) *root.TrustedPublicKeyMaterial {
	return root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		verifier, err := signature.LoadECDSAVerifier(pk.(*ecdsa.PublicKey), crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return &nonExpiringVerifier{verifier}, nil
	})
}
