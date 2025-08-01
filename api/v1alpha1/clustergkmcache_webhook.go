package v1alpha1

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// +kubebuilder:webhook:path=/mutate-gkm-io-v1alpha1-clustergkmcache,mutating=true,failurePolicy=fail,sideEffects=None,groups=gkm.io,resources=clustergkmcaches,verbs=create;update,versions=v1alpha1,name=mclustergkmcache.kb.io,admissionReviewVersions=v1
// +kubebuilder:webhook:path=/validate-gkm-io-v1alpha1-clustergkmcache,mutating=false,failurePolicy=fail,sideEffects=None,groups=gkm.io,resources=clustergkmcaches,verbs=create;update,versions=v1alpha1,name=vclustergkmcache.kb.io,admissionReviewVersions=v1

var (
	clustergkmcacheLog = logf.Log.WithName("clustergkmcache-resource")
)

var _ webhook.CustomValidator = &ClusterGKMCache{}
var _ webhook.CustomDefaulter = &ClusterGKMCache{}

// SetupWebhookWithManager registers the webhook with the controller manager.
func (w *ClusterGKMCache) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(&ClusterGKMCache{}).
		WithDefaulter(w, admission.DefaulterRemoveUnknownOrOmitableFields).
		WithValidator(w).
		Complete()
}

// Default implements the mutating webhook logic for defaulting.
func (w *ClusterGKMCache) Default(_ context.Context, obj runtime.Object) error {
	cache, ok := obj.(*ClusterGKMCache)
	if !ok {
		return apierrors.NewBadRequest(fmt.Sprintf("expected ClusterGKMCache, got %T", obj))
	}

	clustergkmcacheLog.Info("defaulting ClusterGKMCache", "name", cache.Name)

	if cache.Annotations == nil {
		cache.Annotations = map[string]string{}
	}

	// Example: Auto-annotate something if not set
	if _, ok := cache.Annotations["gkm.io/example"]; !ok {
		cache.Annotations["gkm.io/example"] = "defaulted"
	}

	return nil
}

// ValidateCreate implements validation for create events.
func (w *ClusterGKMCache) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	cache, ok := obj.(*ClusterGKMCache)
	if !ok {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("expected ClusterGKMCache, got %T", obj))
	}

	clustergkmcacheLog.Info("validating ClusterGKMCache create", "name", cache.Name)

	if cache.Spec.Image == "" {
		return nil, fmt.Errorf("spec.image must be set")
	}

	if _, exists := cache.Annotations["gkm.io/resolvedDigest"]; exists {
		return nil, fmt.Errorf("annotation gkm.io/resolvedDigest must not be set manually")
	}

	return nil, nil
}

// ValidateUpdate implements validation for update events.
func (w *ClusterGKMCache) ValidateUpdate(_ context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	oldCache, ok1 := oldObj.(*ClusterGKMCache)
	newCache, ok2 := newObj.(*ClusterGKMCache)
	if !ok1 || !ok2 {
		return nil, apierrors.NewBadRequest("type assertion to ClusterGKMCache failed")
	}

	clustergkmcacheLog.Info("validating ClusterGKMCache update", "name", newCache.Name)

	oldDigest := oldCache.Annotations["gkm.io/resolvedDigest"]
	newDigest := newCache.Annotations["gkm.io/resolvedDigest"]

	if oldDigest != newDigest {
		return nil, fmt.Errorf("modification of gkm.io/resolvedDigest is not allowed")
	}

	return nil, nil
}

// ValidateDelete implements validation for delete events.
func (w *ClusterGKMCache) ValidateDelete(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	cache, ok := obj.(*ClusterGKMCache)
	if !ok {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("expected ClusterGKMCache, got %T", obj))
	}

	clustergkmcacheLog.Info("validating ClusterGKMCache delete", "name", cache.Name)

	// Add delete validation logic here if needed.
	return nil, nil
}
